from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub
from datetime import datetime
import csv
import os


class SlicingMonitorController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SlicingMonitorController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.csv_file = 'traffic_data.csv'
        
        # Variabili per lo Slicing Dinamico
        self.video_bytes_prev = 0
        self.fast_lane_active = False
        
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            hub.sleep(10)
            for dp in self.datapaths.values():
                self._request_stats(dp)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _reroute_data_slice(self):
        # Elimina le vecchie regole per il traffico dati forzando gli switch a chiederne di nuove
        for dp in self.datapaths.values():
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            
            # Cancella H2 -> H4
            match1 = parser.OFPMatch(eth_src='00:00:00:00:00:02', eth_dst='00:00:00:00:00:04')
            mod1 = parser.OFPFlowMod(datapath=dp, command=ofproto.OFPFC_DELETE, 
                                     out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                     priority=1, match=match1)
            dp.send_msg(mod1)
            
            # Cancella H4 -> H2
            match2 = parser.OFPMatch(eth_src='00:00:00:00:00:04', eth_dst='00:00:00:00:00:02')
            mod2 = parser.OFPFlowMod(datapath=dp, command=ofproto.OFPFC_DELETE, 
                                     out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                     priority=1, match=match2)
            dp.send_msg(mod2)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        
        # LOGICA DI SLICING DINAMICO SU S1
        if dpid == 1:
            current_video_bytes = 0
            for stat in body:
                if stat.match.get('eth_src') == '00:00:00:00:00:01' and stat.match.get('eth_dst') == '00:00:00:00:00:03':
                    current_video_bytes = stat.byte_count
            
            # Calcolo banda video (Bytes passati negli ultimi 10 sec convertiti in Mbps)
            diff = current_video_bytes - self.video_bytes_prev
            self.video_bytes_prev = current_video_bytes
            bw_mbps = (diff * 8) / (10 * 1000000)
            
            # Se Video < 0.5 Mbps, abilita la Fast Lane per i Dati
            if bw_mbps < 0.5 and not self.fast_lane_active:
                self.logger.info("SLICING DINAMICO: Video Inattivo (%.2f Mbps). Sposto Dati su Slice 10Mbps", bw_mbps)
                self.fast_lane_active = True
                self._reroute_data_slice()
                
            # Se Video >= 0.5 Mbps, riduci i Dati sulla Slow Lane
            elif bw_mbps >= 0.5 and self.fast_lane_active:
                self.logger.info("SLICING DINAMICO: Video Attivo (%.2f Mbps). Ritorno Dati su Slice 1Mbps", bw_mbps)
                self.fast_lane_active = False
                self._reroute_data_slice()

        # Scrittura dati su CSV (Solo su S1 e S6)
        if dpid in [1, 6]:
            file_exists = os.path.isfile(self.csv_file)
            with open(self.csv_file, mode='a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(['timestamp', 'dpid', 'src', 'dst', 'packet_count', 'byte_count'])
                
                for stat in sorted([flow for flow in body if flow.priority == 1],
                                   key=lambda flow: (flow.match.get('eth_src', ''), flow.match.get('eth_dst', ''))):
                    src = stat.match.get('eth_src', 'Sconosciuto')
                    dst = stat.match.get('eth_dst', 'Sconosciuto')
                    
                    if dst != 'ff:ff:ff:ff:ff:ff':
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        writer.writerow([timestamp, dpid, src, dst, stat.packet_count, stat.byte_count])

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return


        src = eth.src
        dst = eth.dst
        out_port = ofproto.OFPP_FLOOD

        # 1. ROUTING DETERMINISTICO (Allineato a slicing_topo.py)
        
        # --- UPPER SLICE (H1 <-> H3) ---
        if src in ['00:00:00:00:00:01', '00:00:00:00:00:03']:
            if src == '00:00:00:00:00:01': # Da H1 verso H3
                if dpid == 1: out_port = 3
                elif dpid == 2: out_port = 2
                elif dpid == 4: out_port = 2
                elif dpid == 6: out_port = 1 # H3 si trova sulla porta 1 di S6
            elif src == '00:00:00:00:00:03': # Da H3 verso H1
                if dpid == 6: out_port = 3 # S4 si trova sulla porta 3 di S6
                elif dpid == 4: out_port = 1
                elif dpid == 2: out_port = 1
                elif dpid == 1: out_port = 1

        # --- LOWER SLICE (H2 <-> H4) DINAMICO ---
        elif src in ['00:00:00:00:00:02', '00:00:00:00:00:04']:
            if src == '00:00:00:00:00:02': # Da H2 verso H4
                if self.fast_lane_active:
                    if dpid == 1: out_port = 3
                    elif dpid == 2: out_port = 2
                    elif dpid == 4: out_port = 2
                    elif dpid == 6: out_port = 2 # H4 si trova sulla porta 2 di S6
                else:
                    if dpid == 1: out_port = 4
                    elif dpid == 3: out_port = 2
                    elif dpid == 5: out_port = 2
                    elif dpid == 6: out_port = 2 # H4 si trova sulla porta 2 di S6
            elif src == '00:00:00:00:00:04': # Da H4 verso H2
                if self.fast_lane_active:
                    if dpid == 6: out_port = 3 # S4 (Fast Lane) è sulla porta 3 di S6
                    elif dpid == 4: out_port = 1
                    elif dpid == 2: out_port = 1
                    elif dpid == 1: out_port = 2
                else:
                    if dpid == 6: out_port = 4 # S5 (Slow Lane) è sulla porta 4 di S6
                    elif dpid == 5: out_port = 1
                    elif dpid == 3: out_port = 1
                    elif dpid == 1: out_port = 2

        # 2. DROP DI SICUREZZA
        if out_port == ofproto.OFPP_FLOOD and dst != 'ff:ff:ff:ff:ff:ff':
            return

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

            if dst != 'ff:ff:ff:ff:ff:ff':
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)