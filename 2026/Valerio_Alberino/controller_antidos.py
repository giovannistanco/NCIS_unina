from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet, ipv4, icmp
from ryu.lib import hub
import json

class AntiDoSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    MONITOR_INTERVAL = 0.5
    THRESHOLD_RATIO  = 0.50   # 50% della capacità nominale del link
    FALLBACK_BW_MBPS = 20     # Soglia base (20 Mbps * 0.50 = 10 Mbps di tolleranza)
    BITS_PER_PKT     = 12000  # Dimensione media pacchetto stimata (1500 byte * 8 bit)

    def __init__(self, *args, **kwargs):
        super(AntiDoSController, self).__init__(*args, **kwargs)
        self.mac_to_port    = {}
        self.datapaths      = {}
        self.flow_history   = {}
        self.blocked_macs   = set()
        self.mac_owner      = {}
        self.port_threshold = {}

        # Carica la mappa di banda se presente
        try:
            with open('/tmp/port_bw.json', 'r') as f:
                raw = json.load(f)
            self.port_bw_map = {
                tuple(int(x) for x in k.split(',')): v
                for k, v in raw.items()
            }
            self.logger.info("[*] Mappa banda caricata: %s", self.port_bw_map)
        except Exception as e:
            self.logger.warning("[!] port_bw.json non trovato: fallback standard a %s Mbps", self.FALLBACK_BW_MBPS)
            self.port_bw_map = {}

        self.monitor_thread = hub.spawn(self._monitor)

    # ------------------------------------------------------------------
    # Metodi di supporto
    # ------------------------------------------------------------------

    def _bw_to_threshold(self, bw_mbps):
        bw_bps = bw_mbps * 1_000_000
        pkts_per_sec = bw_bps * self.THRESHOLD_RATIO / self.BITS_PER_PKT
        return max(1, int(pkts_per_sec * self.MONITOR_INTERVAL))

    def _get_threshold_for_src(self, dpid, src_mac):
        port_no = self.mac_to_port.get(dpid, {}).get(src_mac)
        if port_no is None:
            return self._bw_to_threshold(self.FALLBACK_BW_MBPS)
        return self.port_threshold.get(
            (dpid, port_no),
            self._bw_to_threshold(self.FALLBACK_BW_MBPS)
        )

    def add_flow(self, datapath, priority, match, actions, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod  = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            idle_timeout=idle, hard_timeout=hard,
            match=match, instructions=inst
        )
        datapath.send_msg(mod)

    def _request_port_desc(self, datapath):
        req = datapath.ofproto_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    # ------------------------------------------------------------------
    # Handshake Switch
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

        # Table-Miss default rule (inoltro al controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self._request_port_desc(datapath)
        self.logger.info("[*] Anti-DoS attivo su Switch ID: %s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def _port_desc_reply_handler(self, ev):
        datapath = ev.msg.datapath
        dpid     = datapath.id

        for port in ev.msg.body:
            if port.port_no > 0xffffff00:
                continue

            key = (dpid, port.port_no)
            bw_mbps = self.port_bw_map.get(key, self.FALLBACK_BW_MBPS)
            thr = self._bw_to_threshold(bw_mbps)
            self.port_threshold[key] = thr
            self.logger.info("  [PORTA] dpid=%s porta=%s -> %s Mbps -> soglia=%s pkts/0.5s",
                             dpid, port.port_no, bw_mbps, thr)

    # ------------------------------------------------------------------
    # Monitoraggio periodico flussi
    # ------------------------------------------------------------------

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(self.MONITOR_INTERVAL)

    # ------------------------------------------------------------------
    # Gestione pacchetti e apprendimento MAC / L4
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == 0x88cc:
            return

        src, dst = eth.src, eth.dst
        dpid     = datapath.id

        if src not in self.mac_owner:
            self.mac_owner[src] = dpid

        # Drop immediato se il MAC sorgente è bannato
        if src in self.blocked_macs:
            return

        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether.ETH_TYPE_IP:
                ip_pkt = pkt.get_protocol(ipv4.ipv4)

                # Gestione selettiva ICMP, TCP, UDP
                if ip_pkt.proto in [1, 6, 17]:
                    if ip_pkt.proto == 1:
                        icmp_pkt = pkt.get_protocol(icmp.icmp)

                        # Monitoraggio riservato solo alle Echo Request
                        if icmp_pkt and icmp_pkt.type == 8:
                            match = parser.OFPMatch(
                                eth_type=ether.ETH_TYPE_IP,
                                ip_proto=1,
                                icmpv4_type=8,
                                in_port=in_port,
                                eth_src=src,
                                eth_dst=dst
                            )
                            self.add_flow(datapath, 10, match, actions, idle=10)
                        else:
                            match = parser.OFPMatch(
                                eth_type=ether.ETH_TYPE_IP,
                                ip_proto=1,
                                in_port=in_port,
                                eth_src=src,
                                eth_dst=dst
                            )
                            self.add_flow(datapath, 5, match, actions, idle=10)
                    else:
                        match = parser.OFPMatch(
                            eth_type=ether.ETH_TYPE_IP,
                            ip_proto=ip_pkt.proto,
                            in_port=in_port,
                            eth_src=src,
                            eth_dst=dst
                        )
                        self.add_flow(datapath, 10, match, actions, idle=10)
                else:
                    match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, eth_src=src, eth_dst=dst)
                    self.add_flow(datapath, 5, match, actions, idle=20)

            elif eth.ethertype == ether.ETH_TYPE_ARP:
                match = parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP, eth_src=src, eth_dst=dst)
                self.add_flow(datapath, 20, match, actions, idle=60)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # ------------------------------------------------------------------
    # Ispezione FlowStats e Mitigazione DoS
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body     = ev.msg.body
        datapath = ev.msg.datapath
        dpid     = datapath.id

        for stat in body:
            if stat.priority != 10:
                continue
            if stat.match.get('ip_proto') == 1 and stat.match.get('icmpv4_type') != 8:
                continue

            eth_src = stat.match.get('eth_src')
            eth_dst = stat.match.get('eth_dst')

            if not eth_src or eth_src in self.blocked_macs:
                continue

            # Controllo confinato all'edge switch fisico dell'host
            if dpid != self.mac_owner.get(eth_src):
                continue

            in_port = stat.match.get('in_port')
            if in_port is None and eth_src in self.mac_to_port.get(dpid, {}):
                in_port = self.mac_to_port[dpid][eth_src]

            if in_port is None:
                continue

            flow_key = (dpid, in_port, eth_src, eth_dst)
            current_pkts = stat.packet_count

            if flow_key not in self.flow_history:
                self.flow_history[flow_key] = current_pkts
                continue

            prev_pkts = self.flow_history[flow_key]
            rate = current_pkts - prev_pkts

            if rate <= 0:
                continue

            self.flow_history[flow_key] = current_pkts
            threshold = self._get_threshold_for_src(dpid, eth_src)

            if rate > threshold:
                self.logger.warning("============================================================")
                self.logger.warning("  [ALERT] DoS Rilevato su Switch DPID: %s", dpid)
                self.logger.warning("  Attaccante : %s", eth_src)
                self.logger.warning("  Vittima    : %s", eth_dst)
                self.logger.warning("  Rate       : %s pkts/0.5s > Soglia %s pkts/0.5s", rate, threshold)
                self.logger.warning("  Azione     : Regola DROP installata su tutti gli switch")
                self.logger.warning("============================================================")

                self.blocked_macs.add(eth_src)

                # Regole DROP bidirezionali su tutti gli switch OpenFlow
                for dp_to_ban in self.datapaths.values():
                    p = dp_to_ban.ofproto_parser
                    match_src = p.OFPMatch(eth_src=eth_src, eth_type=ether.ETH_TYPE_IP)
                    self.add_flow(dp_to_ban, 100, match_src, [])
                    match_dst = p.OFPMatch(eth_dst=eth_src, eth_type=ether.ETH_TYPE_IP)
                    self.add_flow(dp_to_ban, 100, match_dst, [])
            else:
                self.logger.info("[OK] %s porta=%s rate=%s pkts/0.5s (sotto soglia %s)",
                                 eth_src, in_port, rate, threshold)