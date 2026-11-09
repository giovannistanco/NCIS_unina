# Controller Ryu (OpenFlow 1.3) per il rilevamento di spoofing e port scan.

import os
import sys
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, ether_types
from ryu.ofproto import ofproto_v1_3

# ryu-manager non aggiunge la cartella del file al path: serve per importare network_config
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from network_config import Topology, ROLE_HONEYPOT

# livelli di risposta
NORMAL = 0
SUSPECT = 1       # solo log
REDIRECT = 2      # il traffico verso il server va all'honeypot
QUARANTINE = 3    # tutto il traffico viene scartato
LEVEL_NAMES = ["NORMAL", "SUSPECT", "REDIRECT", "QUARANTINE"]
THRESHOLDS = {SUSPECT: 12, REDIRECT: 40, QUARANTINE: 70}

W_SCAN = 2          # SYN verso una nuova coppia (ip, porta)
W_SPOOF = 100       # qualsiasi spoofing porta subito in quarantena
HALF_LIFE = 30      # il punteggio si dimezza ogni 30 s
RELEASE_IDLE = 30   # secondi senza traffico bloccato/deviato prima del rilascio

PRIO_QUARANTINE = 300   # sopra la regola ARP: in quarantena si scarta anche l'ARP
PRIO_ARP = 200
PRIO_REDIRECT = 100
PRIO_FWD = 10
PRIO_MISS = 0


def level_for(score):
    for level in (QUARANTINE, REDIRECT, SUSPECT):
        if score >= THRESHOLDS[level]:
            return level
    return NORMAL


def cookie_of(subject):
    # il cookie identifica le regole di sicurezza di una porta: dpid nei bit alti, porta nei bassi
    dpid, port = subject
    return (dpid << 16) | port


def now_str():
    t = time.time()
    return time.strftime("%H:%M:%S", time.localtime(t)) + ".%03d" % (int(t * 1000) % 1000)


class SecurityController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SecurityController, self).__init__(*args, **kwargs)
        self.topo = Topology()
        # tutto è indicizzato per (dpid, porta di bordo), cioè per host
        self.level = {}   # livello attuale
        self.score = {}   # (punteggio, istante dell'ultimo aggiornamento)
        self.seen = {}    # coppie (ip, porta) già contattate
        self.first = {}   # istante del primo evento sospetto

    def add_flow(self, dp, priority, match, actions, idle=0, cookie=0, flags=0):
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                      instructions=inst, idle_timeout=idle,
                                      cookie=cookie, flags=flags))

    def send_packet(self, dp, data, in_port, actions):
        dp.send_msg(dp.ofproto_parser.OFPPacketOut(
            datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
            in_port=in_port, actions=actions, data=data))

    def name_of(self, subject):
        h = self.topo.edge_host(*subject)
        return "%s (s%d:p%d)" % (h.name if h else "?", subject[0], subject[1])

    def current_score(self, subject, now):
        # decadimento esponenziale: score * 0.5^(tempo passato / half life)
        score, t = self.score.get(subject, (0.0, now))
        return score * 0.5 ** ((now - t) / HALF_LIFE)

    # --- CONNESSIONE DI UNO SWITCH ---

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser

        # si parte sempre da tabella vuota
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
                                      table_id=ofp.OFPTT_ALL, out_port=ofp.OFPP_ANY,
                                      out_group=ofp.OFPG_ANY, match=parser.OFPMatch()))
        dp.send_msg(parser.OFPBarrierRequest(dp))   # la cancellazione deve finire prima delle nuove regole

        to_ctrl = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, PRIO_MISS, parser.OFPMatch(), to_ctrl)
        self.add_flow(dp, PRIO_ARP, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP), to_ctrl)
        self.logger.info("switch s%d connesso", dp.id)

    # --- PACKET-IN ---

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(dp, in_port, eth, pkt.get_protocol(arp.arp))
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            self.handle_ip(dp, msg, in_port, eth, pkt)

    def handle_arp(self, dp, in_port, eth, a):
        host = self.topo.edge_host(dp.id, in_port)
        if a is None or host is None:
            return   # l'ARP non viene mai inoltrato, quindi arriva solo dalle porte di bordo
        subject = (dp.id, in_port)
        if self.level.get(subject) == QUARANTINE:
            return

        if host.role != ROLE_HONEYPOT:
            if eth.src != host.mac:
                self.report(dp, subject, W_SPOOF, "MAC spoofing: %s sulla porta di %s" % (eth.src, host.name))
                return
            if a.src_mac != host.mac or (a.src_ip != host.ip and a.src_ip != "0.0.0.0"):
                self.report(dp, subject, W_SPOOF, "ARP spoofing: %s dichiara di avere l'IP %s" % (host.name, a.src_ip))
                return

        # ARP proxy: risponde il controller con il MAC dell'inventario, niente broadcast
        if a.opcode == arp.ARP_REQUEST and a.src_ip != "0.0.0.0":
            owner = self.topo.host_by_ip(a.dst_ip)
            if owner is not None:
                self.send_arp_reply(dp, in_port, a, owner)

    def send_arp_reply(self, dp, in_port, req, owner):
        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(dst=req.src_mac, src=owner.mac,
                                             ethertype=ether_types.ETH_TYPE_ARP))
        reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=owner.mac, src_ip=owner.ip,
                                   dst_mac=req.src_mac, dst_ip=req.src_ip))
        reply.serialize()
        actions = [dp.ofproto_parser.OFPActionOutput(in_port)]
        self.send_packet(dp, reply.data, dp.ofproto.OFPP_CONTROLLER, actions)

    def handle_ip(self, dp, msg, in_port, eth, pkt):
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is None:
            return
        subject = (dp.id, in_port)
        host = self.topo.edge_host(dp.id, in_port)

        # i controlli si fanno solo sulle porte di bordo, l'honeypot è escluso
        if host is not None and host.role != ROLE_HONEYPOT:
            # pacchetti arrivati prima che le regole di blocco fossero attive sullo switch
            if self.enforce(dp, msg, in_port, ip, subject):
                return
            if eth.src != host.mac or ip.src != host.ip:
                self.report(dp, subject, W_SPOOF, "IP spoofing: %s usa MAC %s e IP %s" % (host.name, eth.src, ip.src))
                return
            self.check_scan(dp, subject, pkt, ip)
            # il pacchetto potrebbe aver appena fatto salire il livello
            if self.enforce(dp, msg, in_port, ip, subject):
                return

        out_port = self.topo.out_port(dp.id, eth.dst)
        if out_port is None:
            return
        parser = dp.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(dp, PRIO_FWD, self.flow_match(parser, in_port, eth, ip, pkt), actions, idle=10)
        self.send_packet(dp, msg.data, in_port, actions)

    def flow_match(self, parser, in_port, eth, ip, pkt):
        # regola specifica fino alla porta di destinazione: ogni porta nuova genera un
        # packet-in, ed è così che il controller vede la scansione
        fields = dict(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst,
                      eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip.src,
                      ipv4_dst=ip.dst, ip_proto=ip.proto)
        t = pkt.get_protocol(tcp.tcp)
        u = pkt.get_protocol(udp.udp)
        if t is not None:
            fields['tcp_dst'] = t.dst_port
        elif u is not None:
            fields['udp_dst'] = u.dst_port
        return parser.OFPMatch(**fields)

    def enforce(self, dp, msg, in_port, ip, subject):
        # True se il pacchetto è stato scartato o deviato
        level = self.level.get(subject, NORMAL)
        if level == QUARANTINE:
            return True
        if level == REDIRECT and ip.dst == self.topo.server.ip:
            self.send_packet(dp, msg.data, in_port, self.redirect_actions(dp))
            return True
        return False

    # --- RILEVAMENTO E PUNTEGGIO ---

    def check_scan(self, dp, subject, pkt, ip):
        t = pkt.get_protocol(tcp.tcp)
        # conta solo l'apertura di una connessione (SYN senza ACK)
        if t is None or not (t.bits & tcp.TCP_SYN) or (t.bits & tcp.TCP_ACK):
            return
        target = (ip.dst, t.dst_port)
        seen = self.seen.setdefault(subject, set())
        if target in seen:
            return
        seen.add(target)
        self.report(dp, subject, W_SCAN, "SYN verso %s:%d" % target)

    def report(self, dp, subject, weight, reason):
        now = time.time()
        prev = self.current_score(subject, now)
        if prev < 1 or subject not in self.first:
            self.first[subject] = now   # punteggio tornato quasi a zero: nuovo episodio
        score = prev + weight
        self.score[subject] = (score, now)
        if weight == W_SPOOF:
            self.logger.warning("[%s] ALLARME %s", now_str(), reason)

        old = self.level.get(subject, NORMAL)
        new = level_for(score)
        # si sale subito; si torna indietro qui solo da SUSPECT (non ci sono regole da togliere)
        if new > old or (old == SUSPECT and new == NORMAL):
            self.level[subject] = new
            self.logger.warning("[%s] %s: %s -> %s (punteggio %.1f, %.2f s dal primo evento)",
                                now_str(), self.name_of(subject), LEVEL_NAMES[old],
                                LEVEL_NAMES[new], score, now - self.first[subject])
            if new == REDIRECT:
                self.install_redirect(dp, subject)
            elif new == QUARANTINE:
                self.install_quarantine(dp, subject)
            elif new == NORMAL:
                self.first.pop(subject, None)

    # --- REGOLE DI RISPOSTA ---

    def redirect_actions(self, dp):
        # DNAT: il pacchetto diretto al server viene riscritto verso l'honeypot
        parser = dp.ofproto_parser
        hp = self.topo.honeypot
        return [parser.OFPActionSetField(eth_dst=hp.mac),
                parser.OFPActionSetField(ipv4_dst=hp.ip),
                parser.OFPActionOutput(self.topo.out_port(dp.id, hp.mac))]

    def install_redirect(self, dp, subject):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        hp, srv = self.topo.honeypot, self.topo.server
        attacker = self.topo.edge_host(*subject)

        # andata: attaccante -> server diventa attaccante -> honeypot
        match = parser.OFPMatch(in_port=subject[1], eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=srv.ip)
        self.add_flow(dp, PRIO_REDIRECT, match, self.redirect_actions(dp), idle=RELEASE_IDLE,
                      cookie=cookie_of(subject), flags=ofp.OFPFF_SEND_FLOW_REM)

        # ritorno: le risposte dell'honeypot sembrano arrivare dal server
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=hp.ip, ipv4_dst=attacker.ip)
        actions = [parser.OFPActionSetField(eth_src=srv.mac),
                   parser.OFPActionSetField(ipv4_src=srv.ip),
                   parser.OFPActionOutput(subject[1])]
        self.add_flow(dp, PRIO_REDIRECT, match, actions, cookie=cookie_of(subject))

    def install_quarantine(self, dp, subject):
        parser = dp.ofproto_parser
        match = parser.OFPMatch(in_port=subject[1])
        self.add_flow(dp, PRIO_QUARANTINE, match, [], idle=RELEASE_IDLE,   # nessuna azione = drop
                      cookie=cookie_of(subject), flags=dp.ofproto.OFPFF_SEND_FLOW_REM)

    # --- RILASCIO ---

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed(self, ev):
        # lo switch avvisa quando una regola di blocco/redirect non viene usata per RELEASE_IDLE s
        msg = ev.msg
        dp = msg.datapath
        if msg.reason != dp.ofproto.OFPRR_IDLE_TIMEOUT or msg.cookie == 0:
            return
        subject = (msg.cookie >> 16, msg.cookie & 0xFFFF)
        level = self.level.get(subject, NORMAL)

        # conta solo la regola principale del livello attuale (es. in quarantena si ignora
        # la scadenza della vecchia regola di redirect, che non riceve più traffico)
        main_prio = {REDIRECT: PRIO_REDIRECT, QUARANTINE: PRIO_QUARANTINE}.get(level)
        if msg.priority != main_prio:
            return

        score = self.current_score(subject, time.time())
        if score >= THRESHOLDS[level]:
            # l'host è ancora sospetto (es. scansione lenta verso altri host): si rinnova il blocco
            if level == REDIRECT:
                self.install_redirect(dp, subject)
            else:
                self.install_quarantine(dp, subject)
            return
        self.release(dp, subject, level, msg.packet_count)

    def release(self, dp, subject, level, packets):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        # cancella le altre regole di questo host (es. quella di ritorno del redirect)
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
                                      table_id=ofp.OFPTT_ALL, out_port=ofp.OFPP_ANY,
                                      out_group=ofp.OFPG_ANY, cookie=cookie_of(subject),
                                      cookie_mask=0xFFFFFFFFFFFFFFFF, match=parser.OFPMatch()))
        self.level[subject] = NORMAL
        self.score.pop(subject, None)
        self.seen.pop(subject, None)
        self.first.pop(subject, None)
        self.logger.warning("[%s] %s: %s -> NORMAL (inattivo da %d s, pacchetti scartati/deviati: %d)",
                            now_str(), self.name_of(subject), LEVEL_NAMES[level], RELEASE_IDLE, packets)
