from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                    DEAD_DISPATCHER, set_ev_cls)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, ether_types, arp
from ryu.lib import hub
from ryu.lib.hub import Semaphore
from ryu.app.wsgi import Response, ControllerBase, WSGIApplication, route
import hmac
import ipaddress
import json
import os
import secrets
import time

PRIO_MISS = 0
PRIO_FWD = 10
PRIO_BLOCK = 100

POLL = 2
LOG_MIN_MBPS = 0.5
PROTO = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

# ---------- Parametri della protezione ----------
PROTECTION_ENABLED = os.environ.get('PROTECTION', '1') == '1'
ALPHA = 0.125          # peso dell'EWMA
K_MULTIPLIER = 3       # soglia = media + K * deviazione
MIN_PPS_THRESHOLD = 300  # sotto questo rate (pkt/s) non si allarma mai
HARD_MAX_PPS = 800     # tetto assoluto: evita che la baseline venga "avvelenata"
BASE_BLOCK_TIME = 10   # secondi del primo ban
MAX_BLOCK_TIME = 120   # tetto del backoff esponenziale
DECAY_SECONDS = 60     # ogni DECAY_SECONDS di quiete la penalita' scende di 1
ESCALATE_AT = 2        # dalla 2a violazione della stessa porta: quarantena della porta

# Porte di ACCESSO dei client (dpid -> porte), come da topo.py (verifica con `net` in Mininet:
# s1-eth1:h1, s1-eth2:h2, s2-eth1:h3, s2-eth2:h4). Mai i link tra switch, mai il server.
ACCESS_PORTS = {1: {1, 2}, 2: {1, 2}}

# ---------- Parametri della REST API ----------
PROTECTED_IPS = {'10.0.0.5'}   # il server non si puo' bloccare via API
MAX_API_BLOCK = 3600
AUTH_MAX_FAILS = 5
AUTH_LOCK_SECONDS = 60


def _ts():
    return time.strftime('%H:%M:%S')


class SdnGuard(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.policy_lock = Semaphore()
        self.mac_to_port = {}
        self.datapaths = {}
        self.prev = {}
        self.learned_ip_mac = {}   # binding TOFU {ip: mac}

        # Stato della protezione (condiviso tra detector, enforcer e REST)
        self.blocked = {}     # ('ip', ip) / ('port', dpid, porta) -> istante di scadenza
        self.baselines = {}   # (dpid, porta) -> {'avg', 'dev'}
        self.offenses = {}    # (dpid, porta) -> {'count', 'until'}

        # Autenticazione REST
        self.admin_token = os.environ.get('ADMIN_TOKEN')
        if not self.admin_token:
            self.admin_token = secrets.token_urlsafe(16)
            self.logger.warning("[REST API] ADMIN_TOKEN non impostato: token temporaneo = %s",
                                self.admin_token)
        self.auth_fail = {}   # client -> (tentativi falliti, istante di fine blocco)

        wsgi = kwargs['wsgi']
        wsgi.register(RestFirewallController, {SdnGuard.__name__: self})

        if PROTECTION_ENABLED:
            self.logger.info("--- MODULI DI DIFESA ATTIVI (PROTECTION=1) ---")
        else:
            self.logger.info("--- DIFESE DISATTIVATE (PROTECTION=0) ---")
        hub.spawn(self._monitor)

    # ---------- utilita' ----------
    def _add_flow(self, dp, prio, match, actions, idle=0, hard=0):
        ofp, p = dp.ofproto, dp.ofproto_parser
        inst = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=prio, match=match,
                                 instructions=inst, idle_timeout=idle,
                                 hard_timeout=hard))

    # ---------- connessione switch ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features(self, ev):
        dp = ev.msg.datapath
        ofp, p = dp.ofproto, dp.ofproto_parser
        actions = [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, PRIO_MISS, p.OFPMatch(), actions)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        else:
            self.datapaths.pop(dp.id, None)

    # ---------- guardie anti-spoofing ----------
    def _arp_guard(self, pkt):
        """True = pacchetto ARP da scartare."""
        arp_pkt = pkt.get_protocol(arp.arp)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if not arp_pkt or arp_pkt.src_ip == '0.0.0.0':
            return False
        src_ip, src_mac = arp_pkt.src_ip, arp_pkt.src_mac
        if src_mac != eth_pkt.src:
            self.logger.warning("[%s][ARP Guard] SPOOFING: MAC ARP %s != MAC Ethernet %s (IP %s)",
                                _ts(), src_mac, eth_pkt.src, src_ip)
            return True
        if src_ip not in self.learned_ip_mac:
            self.learned_ip_mac[src_ip] = src_mac
            self.logger.info("[ARP Guard] Appreso binding TOFU: %s -> %s", src_ip, src_mac)
            return False
        if self.learned_ip_mac[src_ip] != src_mac:
            self.logger.warning("[%s][ARP Guard] SPOOFING BLOCCATO: IP %s rivendicato dal MAC %s",
                                _ts(), src_ip, src_mac)
            return True
        return False

    def _ip_guard(self, dp, in_port, eth, ip):
        """True = pacchetto IP da scartare (IP sorgente associato a un altro MAC)."""
        known = self.learned_ip_mac.get(ip.src)
        if known is None or known == eth.src:
            return False
        self.logger.warning("[%s][IP Guard] IP SPOOFING: %s inviato dal MAC %s (atteso %s) su s%d porta %d",
                            _ts(), ip.src, eth.src, known, dp.id, in_port)
        # drop in hardware: senza questa regola ogni pacchetto spoofato salirebbe al controller
        p = dp.ofproto_parser
        match = p.OFPMatch(in_port=in_port, eth_type=0x0800, eth_src=eth.src, ipv4_src=ip.src)
        self._add_flow(dp, PRIO_BLOCK, match, [], idle=10)
        return True

    # ---------- forwarding (learning switch) ----------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, p = dp.ofproto, dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        ip = pkt.get_protocol(ipv4.ipv4)
        if PROTECTION_ENABLED:
            if self._arp_guard(pkt):
                return
            if ip and self._ip_guard(dp, in_port, eth, ip):
                return

        self.mac_to_port.setdefault(dp.id, {})[eth.src] = in_port
        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [p.OFPActionOutput(out_port)]

        # match senza porte L4: un flood con porte variabili resta in un solo flow
        if ip and out_port != ofp.OFPP_FLOOD:
            match = p.OFPMatch(in_port=in_port, eth_type=0x0800,
                               ipv4_src=ip.src, ipv4_dst=ip.dst, ip_proto=ip.proto)
            self._add_flow(dp, PRIO_FWD, match, actions, idle=10)

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(p.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data))

    # ---------- monitor ----------
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(POLL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _stats_reply(self, ev):
        dp = ev.msg.datapath
        dpid = dp.id
        now = time.time()
        udp_per_port = {}   # porta di accesso -> [pps UDP totali, {IP sorgente}]

        for st in ev.msg.body:
            if st.priority != PRIO_FWD:
                continue
            m = st.match
            key = (dpid, m['in_port'], m['ipv4_src'], m['ipv4_dst'], m['ip_proto'])
            pb, pp = self.prev.get(key, (0, 0))
            db = st.byte_count - pb if st.byte_count >= pb else st.byte_count
            dpk = st.packet_count - pp if st.packet_count >= pp else st.packet_count
            self.prev[key] = (st.byte_count, st.packet_count)

            mbps = db * 8 / POLL / 1e6
            pps = dpk / POLL
            if mbps >= LOG_MIN_MBPS:
                self.logger.info("[Monitor] s%d p%d: %s -> %s %-4s | %6.1f Mbit/s | %6d pkt/s",
                                 dpid, m['in_port'], m['ipv4_src'], m['ipv4_dst'],
                                 PROTO.get(m['ip_proto'], m['ip_proto']), mbps, pps)

            # si misura per PORTA di accesso, sommando tutti i flussi UDP:
            # cambiare IP, MAC o destinazione non resetta il conteggio
            if m['ip_proto'] == 17 and m['in_port'] in ACCESS_PORTS.get(dpid, ()):
                entry = udp_per_port.setdefault(m['in_port'], [0.0, set()])
                entry[0] += pps
                entry[1].add(m['ipv4_src'])

        if PROTECTION_ENABLED:
            for port, (pps, ips) in udp_per_port.items():
                hub.spawn(self._dos_detector_enforcer, dpid, port, pps, ips, now)

    # ---------- detector + enforcer ----------
    def _dos_detector_enforcer(self, dpid, port, pps, ips, now):
        key = (dpid, port)
        with self.policy_lock:
            # porta in quarantena: niente da fare
            if now <= self.blocked.get(('port', dpid, port), 0):
                return

            b = self.baselines.setdefault(key, {'avg': float(min(pps, MIN_PPS_THRESHOLD)), 'dev': 0.0})
            threshold = min(HARD_MAX_PPS, max(MIN_PPS_THRESHOLD, b['avg'] + K_MULTIPLIER * b['dev']))

            if pps <= threshold:
                diff = pps - b['avg']
                b['avg'] += ALPHA * diff
                b['dev'] = (1 - ALPHA) * b['dev'] + ALPHA * abs(diff)
                return

            # --- violazione ---
            off = self.offenses.setdefault(key, {'count': 0, 'until': 0.0})
            if off['until']:
                quiet_steps = int((now - off['until']) // DECAY_SECONDS)   # decadimento della penalita'
                off['count'] = max(0, off['count'] - max(0, quiet_steps))
            off['count'] += 1
            duration = min(MAX_BLOCK_TIME, BASE_BLOCK_TIME * 2 ** (off['count'] - 1))
            off['until'] = now + duration

            self.logger.warning("[%s][Detector] ATTACCO su s%d porta %d: %d pkt/s (soglia %d) da %s | violazione #%d",
                                _ts(), dpid, port, pps, threshold, sorted(ips), off['count'])

            dp = self.datapaths.get(dpid)
            if dp is None:
                return
            p = dp.ofproto_parser
            if off['count'] >= ESCALATE_AT:
                # recidiva (anche con IP/MAC cambiati): quarantena della porta di accesso
                self._add_flow(dp, PRIO_BLOCK, p.OFPMatch(in_port=port, eth_type=0x0800), [], hard=duration)
                self.blocked[('port', dpid, port)] = now + duration
                self.logger.warning("[%s][Enforcer] QUARANTENA porta %d di s%d per %d s", _ts(), port, dpid, duration)
            else:
                for ip in ips:
                    match = p.OFPMatch(in_port=port, eth_type=0x0800, ipv4_src=ip)
                    self._add_flow(dp, PRIO_BLOCK, match, [], hard=duration)
                    self.blocked[('ip', ip)] = now + duration
                    self.logger.warning("[%s][Enforcer] Blocco IP %s sulla porta %d di s%d per %d s",
                                        _ts(), ip, port, dpid, duration)


# ================= REST API AMMINISTRATIVA =================
class RestFirewallController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data[SdnGuard.__name__]

    @staticmethod
    def _json(obj, status=200):
        return Response(content_type='application/json',
                        body=json.dumps(obj).encode('utf-8'), status=status)

    def _check_auth(self, req):
        """None se autenticato, altrimenti la Response di errore."""
        app = self.app
        client = req.remote_addr or '?'
        now = time.time()
        fails, lock_until = app.auth_fail.get(client, (0, 0.0))
        if now < lock_until:
            return self._json({"status": "error", "msg": "troppi tentativi falliti, riprova piu' tardi"}, 429)
        auth = req.headers.get('Authorization', '')
        supplied = auth[7:] if auth.startswith('Bearer ') else ''
        if hmac.compare_digest(supplied.encode('utf-8'), app.admin_token.encode('utf-8')):
            app.auth_fail.pop(client, None)
            return None
        fails += 1
        lock = now + AUTH_LOCK_SECONDS if fails >= AUTH_MAX_FAILS else 0.0
        app.auth_fail[client] = (0 if lock else fails, lock)
        app.logger.warning("[%s][REST API] Autenticazione FALLITA da %s (tentativo %d)", _ts(), client, fails)
        return self._json({"status": "error", "msg": "non autorizzato"}, 401)

    @route('firewall', '/firewall/block', methods=['POST'])
    def block_ip(self, req, **kwargs):
        denied = self._check_auth(req)
        if denied:
            return denied
        try:
            body = req.json
            ip = str(ipaddress.IPv4Address(str(body.get('ip', ''))))
            duration = int(body.get('duration', 60))
        except Exception:
            return self._json({"status": "error",
                               "msg": "payload non valido, atteso {\"ip\": \"a.b.c.d\", \"duration\": secondi}"}, 400)
        if ip in PROTECTED_IPS:
            return self._json({"status": "error", "msg": "IP protetto, non bloccabile"}, 403)
        duration = max(1, min(duration, MAX_API_BLOCK))
        app = self.app
        now = time.time()
        with app.policy_lock:
            app.blocked[('ip', ip)] = now + duration
            for dp in list(app.datapaths.values()):
                match = dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
                app._add_flow(dp, PRIO_BLOCK, match, [], hard=duration)
        app.logger.warning("[%s][REST API] Amministratore: bloccato %s per %d s", _ts(), ip, duration)
        return self._json({"status": "success", "msg": "IP %s bloccato per %d s" % (ip, duration)})

    @route('firewall_list', '/firewall/blocklist', methods=['GET'])
    def list_blocks(self, req, **kwargs):
        denied = self._check_auth(req)
        if denied:
            return denied
        now = time.time()
        with self.app.policy_lock:
            items = [{"target": "/".join(str(x) for x in k), "remaining_s": int(v - now)}
                     for k, v in self.app.blocked.items() if v > now]
        return self._json({"blocked": items})