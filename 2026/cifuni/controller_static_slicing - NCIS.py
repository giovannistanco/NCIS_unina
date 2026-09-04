# (Copyright Nippon Telegraph and Telephone Corp.)
# Modificato per il progetto di Topology Slicing.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

"RICORDA: ofproto = OpenFlow Protocol, per comunicare con switch ryu usa questo protocollo -> serve ad es. un parser"
class TopologySlicingSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # dpid -> {porta_ingresso: porta_uscita}
    SLICE_TABLE = {
        1: {1: 3, 3: 1, 2: 4, 4: 2},  
        2: {1: 2, 2: 1},          # s2 e 3 sono solo di transito -> solo 2 porte    
        3: {1: 2, 2: 1},              
        4: {1: 3, 3: 1, 2: 4, 4: 2},  
    }
    "Questo dizionario associa il datapath id (id dello switch) al dict che contiene le regole"
    "Le regole dipendono dalla topolgia def., infatti le porte degli switch sono NUMERATE SEQ. "
    "in base agli addLink fatti in topologia (conta #volte comparso s1 prima)"

    def __init__(self, *args, **kwargs):
        super(TopologySlicingSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    "Metodo usato nell'handshake/iniz. tra switch e controller ryu"
    "Il decoratore rende il metodo un hadler che scatta l'evento OF"
    "Ciò accade non appena i 2 si connettono. Dispatcher: negoziazione, configuraz. "
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath  #switch appena connesso
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # table-miss: tutto cio' che non matcha nessuna regola va al controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def _get_slice_out_port(self, dpid, in_port):
        return self.SLICE_TABLE.get(dpid, {}).get(in_port)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        self.logger.info("packet in dpid=%s src=%s dst=%s in_port=%s",
                          dpid, src, dst, in_port)

        
        out_port = self._get_slice_out_port(dpid, in_port)

        if out_port is None:
            self.logger.warning(
                "Nessuna regola di slicing per dpid=%s in_port=%s: scarto il pacchetto",
                dpid, in_port)
            return

        actions = [parser.OFPActionOutput(out_port)]

        
        match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)

        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 10, match, actions, msg.buffer_id)
            return
        else:
            self.add_flow(datapath, 10, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        
        
