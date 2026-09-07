#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ryu_firewall.py
================================================================
Controller SDN basato su Ryu e OpenFlow 1.3 per la rilevazione e la mitigazione
di un attacco botnet "stealth" a livello del layer di applicazione, basato sul Message
Innovation Rate (MIR) con soglia dinamica.

Architettura modulare:
 - Monitor    : ispezione DPI ed estrazione request-line HTTP
 - Analyzer   : calcolo periodico del MIR locale e globale
 - REST API   : interfaccia di controllo per lo sblocco manuale
"""

import json
import time
from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp
from ryu.lib import hub
from ryu.app.wsgi import ControllerBase, WSGIApplication, route, Response


# ===========================================================================
# CONFIGURAZIONE TOPOLOGICA E PARAMETRICA
# ===========================================================================

SERVER_IP = '10.0.0.1'         # IP del Server Target (h1)
HTTP_PORT = 80                  # porta applicativa monitorata
SERVER_EDGE_DPID = 4            # switch Edge collegato al server (unico punto di DPI)

# Mappatura statica
IP_TO_EDGE_DPID = {
    '10.0.0.1': 4,   # h1 - Server Target     (Edge1 / s4)
    '10.0.0.2': 4,   # h2 - Utente legittimo  (Edge1 / s4)
    '10.0.0.3': 5,   # h3 - Utente legittimo  (Edge2 / s5)
    '10.0.0.4': 6,   # h4 - Utente legittimo  (Edge3 / s6)
    '10.0.0.5': 6,   # h5 - Bot               (Edge3 / s6)
    '10.0.0.6': 7,   # h6 - Bot               (Edge4 / s7)
}

KNOWN_BOT_IPS = {'10.0.0.5', '10.0.0.6'}
KNOWN_LEGIT_IPS = {'10.0.0.2', '10.0.0.3', '10.0.0.4'}

# --- Parametri dell'algoritmo di rilevamento ---
MONITOR_WINDOW = 10          # T: ampiezza finestra temporale (s)
MIN_PACKETS_FOR_CHECK = 10   # soglia minima di N per considerare attendibile il MIR locale
MIR_DELTA = 0.3              # margine sotto al MIR globale per far scattare l'allarme

# --- Priorità dei flow ---
HTTP_TRAP_PRIORITY = 100
TRANSIT_PRIORITY = 10
LEARNING_PRIORITY = 1
BLOCK_PRIORITY = 200
BLOCK_HARD_TIMEOUT = 60      # durata (s) della regola di drop -> auto-ripristino

# --- REST / logging ---
IP_PATTERN = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
METRICS_LOG_PATH = 'mir_metrics.jsonl'
firewall_instance_name = 'firewall_api_app'


# ===========================================================================
# ENFORCER
# ===========================================================================
class Enforcer:
    """
    Costruisce e invia messaggi OpenFlow. Riceve richieste
    sia dall'Analyzer per il rilevamento automatico via MIR sia dalla REST
    API per la decisione umana/esterna attraverso gli stessi due metodi
    pubblici block_ip() / unblock_ip(). Non c'è privilegio tra i canali
    """

    def __init__(self, app):
        self.app = app
        self.logger = app.logger
        self.datapaths = {}      # {dpid: datapath}
        self.blocklist = {}      # {ip: {blocked_at, expires_at, reason, source, edge_dpid}}
        self._lock = hub.Semaphore(1)   # protegge datapaths e blocklist (3 thread concorrenti)

    # ------------------------------------------------------------------
    # Registrazione e setup switch
    # ------------------------------------------------------------------
    def register_datapath(self, datapath):
        with self._lock:
            self.datapaths[datapath.id] = datapath
        self.logger.info("[ENFORCER] Switch connesso: dpid=%s", datapath.id)

    def setup_switch(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

        if datapath.id == SERVER_EDGE_DPID:
            match_http = parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                                          ipv4_dst=SERVER_IP, tcp_dst=HTTP_PORT)
            actions_http = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, priority=HTTP_TRAP_PRIORITY, match=match_http, actions=actions_http)
            self.logger.info("[ENFORCER] Patch proattiva HTTP (priority=%d) installata su dpid=%s",
                              HTTP_TRAP_PRIORITY, datapath.id)

    # ------------------------------------------------------------------
    # Primitive OpenFlow
    # ------------------------------------------------------------------
    def add_flow(self, datapath, priority, match, actions, hard_timeout=0, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                 instructions=inst, hard_timeout=hard_timeout,
                                 idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    def remove_flow(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE_STRICT,
                                 priority=priority, match=match,
                                 out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
        datapath.send_msg(mod)

    def packet_out(self, datapath, msg, in_port, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # ------------------------------------------------------------------
    # Forwarding ordinario
    # ------------------------------------------------------------------
    def install_transit_bypass(self, datapath, src_ip, dst_ip, actions):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                                 ipv4_src=src_ip, ipv4_dst=dst_ip, tcp_dst=HTTP_PORT)
        self.add_flow(datapath, priority=TRANSIT_PRIORITY, match=match, actions=actions)

    def install_l2_learning(self, datapath, in_port, eth_src, eth_dst, actions):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port, eth_src=eth_src, eth_dst=eth_dst)
        self.add_flow(datapath, priority=LEARNING_PRIORITY, match=match, actions=actions)

    # ------------------------------------------------------------------
    # Blocklist
    # ------------------------------------------------------------------
    def block_ip(self, ip, reason, source, duration=BLOCK_HARD_TIMEOUT):
        """
        Punto di ingresso per qualunque richiesta di blocco.
        Ritorna (ok: bool, http_status: int, message: str).
        """
        with self._lock:
            now = time.time()
            existing = self.blocklist.get(ip)
            if existing and existing['expires_at'] > now:
                remaining = round(existing['expires_at'] - now, 1)
                return False, 409, f"{ip} e' già bloccato (scade tra {remaining}s)"

            edge_dpid = IP_TO_EDGE_DPID.get(ip)
            if edge_dpid is None:
                return False, 404, f"{ip} non e' un host noto della topologia"

            datapath = self.datapaths.get(edge_dpid)
            if datapath is None:
                return False, 503, f"switch Edge dpid={edge_dpid} non ancora connesso al controller"

            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            self.add_flow(datapath, priority=BLOCK_PRIORITY, match=match,
                          actions=[], hard_timeout=duration)   # azioni vuote = drop

            self.blocklist[ip] = {'blocked_at': now, 'expires_at': now + duration,
                                   'reason': reason, 'source': source, 'edge_dpid': edge_dpid}

        msg = f"{ip} bloccato per {duration}s su dpid={edge_dpid} (motivo: {reason}; origine: {source})"
        self.logger.warning("[MITIGAZIONE] *** %s ***", msg)
        return True, 200, msg

    def unblock_ip(self, ip):
        """
        Sblocco anticipato.
        Rimuove la entry OpenFlow prima della scadenza naturale
        dell'hard_timeout, invece di aspettarla passivamente.
        """
        with self._lock:
            entry = self.blocklist.pop(ip, None)
            if entry is None:
                return False, 404, f"{ip} non risulta attualmente bloccato"

            datapath = self.datapaths.get(entry['edge_dpid'])
            if datapath is not None:
                parser = datapath.ofproto_parser
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
                self.remove_flow(datapath, priority=BLOCK_PRIORITY, match=match)

        msg = f"{ip} sbloccato manualmente (era bloccato per: {entry['reason']})"
        self.logger.warning("[SBLOCCO MANUALE] *** %s ***", msg)
        return True, 200, msg

    def expire_blocks(self):
        """Auto-ripristino passivo: rimuove dal dizionario le entry
        il cui hard_timeout è scaduto sullo switch, ovvero per le quali
        la regola OpenFlow è già stata rimossa autonomamente dallo switch."""
        with self._lock:
            now = time.time()
            expired = [ip for ip, e in self.blocklist.items() if e['expires_at'] <= now]
            for ip in expired:
                del self.blocklist[ip]
        return expired

    def get_blocklist(self):
        with self._lock:
            now = time.time()
            return [
                {'ip': ip, 'reason': e['reason'], 'source': e['source'],
                 'blocked_at': e['blocked_at'], 'expires_at': e['expires_at'],
                 'remaining_s': max(0.0, round(e['expires_at'] - now, 1))}
                for ip, e in self.blocklist.items()
            ]


# ===========================================================================
# MONITOR
# ===========================================================================
class Monitor:

    def __init__(self, app, enforcer, analyzer):
        self.app = app
        self.logger = app.logger
        self.enforcer = enforcer
        self.analyzer = analyzer
        self.mac_to_port = {}   # {dpid: {mac: port}}

    def handle_packet_in(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.mac_to_port.setdefault(dpid, {})
        src, dst = eth.src, eth.dst
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        is_http_to_server = (ip_pkt is not None and tcp_pkt is not None and
                              ip_pkt.dst == SERVER_IP and tcp_pkt.dst_port == HTTP_PORT)

        if is_http_to_server and dpid == SERVER_EDGE_DPID:
            t0 = time.perf_counter()
            request_line = self._extract_http_request_line(pkt)
            latency_s = time.perf_counter() - t0
            if request_line is not None:
                self.analyzer.record_http(ip_pkt.src, request_line, latency_s)

        elif is_http_to_server:
            self.enforcer.install_transit_bypass(datapath, ip_pkt.src, ip_pkt.dst, actions)

        elif out_port != ofproto.OFPP_FLOOD:
            # Traffico generico (ARP, ICMP, risposte TCP, pingall, ecc.)
            self.enforcer.install_l2_learning(datapath, in_port, src, dst, actions)

        self.enforcer.packet_out(datapath, msg, in_port, actions)

    @staticmethod
    def _extract_http_request_line(pkt):
        """
        Estrae la request-line HTTP (es. "GET /path HTTP/1.1") dal
        payload del pacchetto, se presente.
        """
        payload = None
        if pkt.protocols and isinstance(pkt.protocols[-1], bytes):
            payload = pkt.protocols[-1]
        if not payload:
            return None  # pacchetto TCP senza dati applicativi (es. puro ACK)

        try:
            text = payload.decode('utf-8', errors='ignore').strip()
        except Exception:
            return None

        if not text.startswith('GET'):
            return None  # segmenti senza una request-line GET ignorati

        return text.split('\r\n', 1)[0]


# ===========================================================================
# ANALYZER
# ===========================================================================
class Analyzer:

    def __init__(self, app, enforcer):
        self.app = app
        self.logger = app.logger
        self.enforcer = enforcer
        self.window_stats = defaultdict(lambda: {'count': 0, 'unique_payloads': set(), 'latencies': []})
        self._lock = hub.Semaphore(1)
        self._window_id = 0
        self.thread = hub.spawn(self._loop)   # [Difetto #7] thread indipendente

    def record_http(self, src_ip, request_line, processing_latency_s):
        with self._lock:
            stats = self.window_stats[src_ip]
            stats['count'] += 1
            stats['unique_payloads'].add(request_line)
            stats['latencies'].append(processing_latency_s)

    def _loop(self):
        while True:
            hub.sleep(MONITOR_WINDOW)
            try:
                self._evaluate_window()
            except Exception:
                self.logger.exception("[ANALYZER] errore inatteso durante la valutazione della finestra")

    def _evaluate_window(self):
        with self._lock:
            snapshot = self.window_stats
            self.window_stats = defaultdict(lambda: {'count': 0, 'unique_payloads': set(), 'latencies': []})

        self._window_id += 1
        now = time.time()

        for ip in self.enforcer.expire_blocks():
            self.logger.info("[AUTO-RIPRISTINO] Blocco per %s scaduto (hard_timeout): host nuovamente monitorato.", ip)

        if not snapshot:
            self.logger.info("[MIR] Finestra #%d: nessun traffico HTTP osservato.", self._window_id)
            self._log_eta(now)
            return

        local_mir = {ip: len(s['unique_payloads']) / s['count']
                     for ip, s in snapshot.items() if s['count'] > 0}
        if not local_mir:
            self._log_eta(now)
            return

        mir_globale = sum(local_mir.values()) / len(local_mir)
        soglia = mir_globale - MIR_DELTA

        self.logger.info("[MIR] Finestra #%d  host attivi=%d  MIR_globale=%.3f  soglia=%.3f",
                          self._window_id, len(local_mir), mir_globale, soglia)

        for ip, mir in local_mir.items():
            n = snapshot[ip]['count']
            u = len(snapshot[ip]['unique_payloads'])
            lat = snapshot[ip]['latencies']
            avg_latency_ms = (sum(lat) / len(lat) * 1000.0) if lat else 0.0
            throughput_rps = n / MONITOR_WINDOW

            sospetto = n > MIN_PACKETS_FOR_CHECK and mir < soglia

            self.logger.info("    %-12s N=%-4d U=%-4d MIR=%.3f thr=%.2freq/s lat=%.3fms%s",
                              ip, n, u, mir, throughput_rps, avg_latency_ms,
                              "  <-- SOSPETTO BOT" if sospetto else "")

            # log strutturato per i grafici del report
            self._write_record({
                'type': 'host_window', 'window': self._window_id, 'ts': now, 'ip': ip,
                'n': n, 'u': u, 'mir_local': round(mir, 4), 'mir_global': round(mir_globale, 4),
                'threshold': round(soglia, 4), 'flagged': sospetto,
                'throughput_rps': round(throughput_rps, 3),
                'avg_latency_ms': round(avg_latency_ms, 4),
            })

            if sospetto:
                ok, _status, msg = self.enforcer.block_ip(
                    ip, reason=f"MIR {mir:.3f} < soglia {soglia:.3f} (N={n})",
                    source='ANALYZER-MIR')
                if ok:
                    self.logger.warning("[ANALYZER->ENFORCER] %s", msg)

        self._log_eta(now)

    def _log_eta(self, now):
        banned = {e['ip'] for e in self.enforcer.get_blocklist()}
        eta_bot = len(banned & KNOWN_BOT_IPS) / len(KNOWN_BOT_IPS) if KNOWN_BOT_IPS else 0.0
        eta_nor = len(banned & KNOWN_LEGIT_IPS) / len(KNOWN_LEGIT_IPS) if KNOWN_LEGIT_IPS else 0.0

        self.logger.info("[EVAL] eta_bot(t)=%.2f  eta_nor(t)=%.2f  banned=%s",
                          eta_bot, eta_nor, sorted(banned))
        self._write_record({'type': 'eta_summary', 'window': self._window_id, 'ts': now,
                             'eta_bot': round(eta_bot, 3), 'eta_nor': round(eta_nor, 3),
                             'banned_ips': sorted(banned)})

    @staticmethod
    def _write_record(record):
        try:
            with open(METRICS_LOG_PATH, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record) + '\n')
        except OSError:
            pass  # scrittura del log metriche non bloccante per il controller


# ===========================================================================
# APPLICAZIONE RYU PRINCIPALE
# ===========================================================================
class StealthBotnetFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(StealthBotnetFirewall, self).__init__(*args, **kwargs)

        self.enforcer = Enforcer(self)
        self.analyzer = Analyzer(self, self.enforcer)
        self.monitor = Monitor(self, self.enforcer, self.analyzer)

        self.datapaths = self.enforcer.datapaths

        wsgi = kwargs['wsgi']
        wsgi.register(FirewallController, {firewall_instance_name: self})

        self.logger.info("=== Stealth Botnet Firewall v2 (modulare + REST) avviato "
                          "(T=%ss, N_min=%s, delta=%.2f, blocco=%ss) ===",
                          MONITOR_WINDOW, MIN_PACKETS_FOR_CHECK, MIR_DELTA, BLOCK_HARD_TIMEOUT)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.enforcer.register_datapath(datapath)
        self.enforcer.setup_switch(datapath)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self.monitor.handle_packet_in(ev)


# ===========================================================================
# REST API
# ===========================================================================
class FirewallController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(FirewallController, self).__init__(req, link, data, **config)
        self.app = data[firewall_instance_name]

    @route('firewall', '/firewall/blocklist', methods=['GET'])
    def list_blocklist(self, req, **kwargs):
        body = json.dumps(self.app.enforcer.get_blocklist())
        return Response(content_type='application/json', text=body)

    @route('firewall', '/firewall/block', methods=['POST'])
    def block_ip(self, req, **kwargs):
        try:
            data = req.json if req.body else {}
        except ValueError:
            return Response(status=400, content_type='application/json',
                             text=json.dumps({'error': 'corpo JSON non valido'}))

        ip = data.get('ip')
        if not ip:
            return Response(status=400, content_type='application/json',
                             text=json.dumps({'error': "campo 'ip' obbligatorio"}))

        reason = data.get('reason', 'blocco manuale via REST')
        duration = data.get('duration', BLOCK_HARD_TIMEOUT)
        ok, status, msg = self.app.enforcer.block_ip(ip, reason=reason, source='REST', duration=duration)
        return Response(status=status, content_type='application/json', text=json.dumps({'result': msg}))

    @route('firewall', '/firewall/block/{ip}', methods=['DELETE'], requirements={'ip': IP_PATTERN})
    def unblock_ip(self, req, ip, **kwargs):
        ok, status, msg = self.app.enforcer.unblock_ip(ip)
        return Response(status=status, content_type='application/json', text=json.dumps({'result': msg}))
