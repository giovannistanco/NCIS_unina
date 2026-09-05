#!/usr/bin/env python3

import time
import threading
from collections import deque, defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, ether_types
from ryu.lib import hub


PORT_SCAN_WINDOW_SEC = 5        # ampiezza della sliding window
PORT_SCAN_THRESHOLD = 8         # numero di (dst_ip,dst_port) distinti in finestra -> alert
QUARANTINE_TIMEOUT_SEC = 30     # dopo quanto tempo di "silenzio" un host viene sbloccato
FLOW_IDLE_TIMEOUT = 0           # le regole di blocco restano finché non vengono rimosse


class MitigationManager:
    """Struttura dati condivisa: gestisce la quarantena in modo
    indipendente dai moduli di detection, cosi' piu' fonti possono contribuire
    alle stesse policy invece di avere un unico punto decisionale rigido."""

    def __init__(self, logger):
        self.logger = logger
        self.lock = threading.Lock()
        self.quarantined = {}

    def is_quarantined(self, mac):
        with self.lock:
            return mac in self.quarantined

    def quarantine(self, datapath, mac, reason, install_cb):
        with self.lock:
            already = mac in self.quarantined
            self.quarantined[mac] = {
                "reason": reason,
                "datapath": datapath,
                "expire": time.time() + QUARANTINE_TIMEOUT_SEC,
            }
        if not already:
            self.logger.warning("[MITIGATION] Host %s messo in QUARANTENA (%s)", mac, reason)
            install_cb(datapath, mac)
        else:
            # violazione ripetuta: rinnova il timeout, non serve reinstallare la regola
            self.logger.info("[MITIGATION] Host %s ancora in violazione (%s), timeout rinnovato", mac, reason)

    def sweep_expired(self, remove_cb):
        """Da chiamare periodicamente: rimuove dalla quarantena gli host il cui timeout e' scaduto senza nuove
        violazioni implementando quindi lo sblocco dinamico"""
        now = time.time()
        expired = []
        with self.lock:
            for mac, info in list(self.quarantined.items()):
                if info["expire"] <= now:
                    expired.append((mac, info["datapath"]))
                    del self.quarantined[mac]
        for mac, dp in expired:
            self.logger.warning("[MITIGATION] Timeout scaduto: sblocco host %s", mac)
            remove_cb(dp, mac)


class ArpSpoofDetector:
    """Dynamic ARP Inspection semplificata: la prima associazione tra IP e MAC vista
    diventa quella che il sistema si aspetta. Se lo stesso IP appare con un MAC diverso 
    da quello atteso scatta l'allarme."""

    def __init__(self, logger):
        self.logger = logger
        self.bindings = {}  # ip -> mac

    def check(self, src_ip, src_mac):
        trusted_mac = self.bindings.get(src_ip)
        if trusted_mac is None:
            self.bindings[src_ip] = src_mac
            return False, None
        if trusted_mac != src_mac:
            return True, (
                f"ARP spoofing sospetto: IP {src_ip} associato a {trusted_mac}, "
                f"ma ora annunciato da {src_mac}"
            )
        return False, None


class PortScanDetector:
    """Rileva host che contattano molte combinazioni (dst_ip, dst_port)
    distinte in una finestra temporale breve (caratteristico di una scansione nmap)"""

    def __init__(self, logger):
        self.logger = logger
        self.activity = defaultdict(deque)  # src_ip -> deque[(ts, dst_ip, dst_port)]

    def check(self, src_ip, dst_ip, dst_port):
        now = time.time()
        dq = self.activity[src_ip]
        dq.append((now, dst_ip, dst_port))

        # scarta gli eventi fuori dalla finestra
        while dq and now - dq[0][0] > PORT_SCAN_WINDOW_SEC:
            dq.popleft()

        distinct_targets = {(d_ip, d_port) for _, d_ip, d_port in dq}
        if len(distinct_targets) >= PORT_SCAN_THRESHOLD:
            return True, (
                f"Port scan sospetto: {src_ip} ha contattato "
                f"{len(distinct_targets)} combinazioni (ip,porta) distinte "
                f"in {PORT_SCAN_WINDOW_SEC}s"
            )
        return False, None


class SecurityIDPS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SecurityIDPS, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

        self.arp_detector = ArpSpoofDetector(self.logger)
        self.scan_detector = PortScanDetector(self.logger)
        self.mitigation = MitigationManager(self.logger)

        # thread separato per lo sblocco dinamico (sweep periodico)
        self.monitor_thread = hub.spawn(self._monitor)

    # Setup switch 
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # regola di default: manda tutto al controller (table-miss)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                           ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                 match=match, instructions=inst,
                                 idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    # installazione / rimozione regole di quarantena
    def _install_quarantine_rule(self, datapath, mac):
        parser = datapath.ofproto_parser
        # priorita' alta, sopra le regole di forwarding normali: droppa
        # tutto cio' che arriva da quel MAC.
        match = parser.OFPMatch(eth_src=mac)
        self.add_flow(datapath, priority=100, match=match, actions=[])

    def _remove_quarantine_rule(self, datapath, mac):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=mac)
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                 out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                 priority=100, match=match)
        datapath.send_msg(mod)

    def _monitor(self):
        """Thread separato: sblocco dinamico degli host in quarantena
        (invece che bloccare per sempre o non sbloccare mai)."""
        while True:
            self.mitigation.sweep_expired(self._remove_quarantine_rule)
            hub.sleep(5)

    # Packet-in: switching L2 + detection
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src_mac = eth.src
        dst_mac = eth.dst
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # se l'host e' in quarantena, non processiamo oltre
        if self.mitigation.is_quarantined(src_mac):
            return

        # ARP spoofing detection
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            is_spoof, reason = self.arp_detector.check(arp_pkt.src_ip, arp_pkt.src_mac)
            if is_spoof:
                self.mitigation.quarantine(datapath, arp_pkt.src_mac, reason,
                                            self._install_quarantine_rule)
                return  # non inoltriamo il pacchetto malevolo

        # port scan detection (su pacchetti TCP)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if ip_pkt and tcp_pkt:
            is_scan, reason = self.scan_detector.check(ip_pkt.src, ip_pkt.dst, tcp_pkt.dst_port)
            if is_scan:
                self.mitigation.quarantine(datapath, src_mac, reason,
                                            self._install_quarantine_rule)
                return

        # learning switch standard
        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self.add_flow(datapath, priority=10, match=match, actions=actions,
                           idle_timeout=30)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
