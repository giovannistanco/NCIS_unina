# (Copyright Nippon Telegraph and Telephone Corp.)
# Modificato per il progetto di Service Slicing.
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
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp


class ServiceSlicingSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    VIDEO_UDP_PORT = 9999

    # Switch "edge" con host locali + 2 uplink (upper/lower)
    EDGE_SWITCHES = {
        1: {'local_ports': (1, 2), 'upper_port': 3, 'lower_port': 4},
        4: {'local_ports': (1, 2), 'upper_port': 3, 'lower_port': 4},
    }

    # Switch di puro transito (2 sole porte, pass-through)
    RELAY_SWITCHES = {
        2: {1: 2, 2: 1},
        3: {1: 2, 2: 1},
    }

    def __init__(self, *args, **kwargs):
        super(ServiceSlicingSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
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

    @staticmethod
    def _is_video(pkt):
        """Rest. True se il pacchetto e' UDP con porta destinazione 9999 (video)."""
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return False
        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt is None:
            return False
        return udp_pkt.dst_port == ServiceSlicingSwitch13.VIDEO_UDP_PORT

    def _install_and_send(self, datapath, msg, priority, match, actions, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, priority, match, actions, msg.buffer_id)
            return
        else:
            self.add_flow(datapath, priority, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

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

       
        if dpid in self.RELAY_SWITCHES:
            out_port = self.RELAY_SWITCHES[dpid].get(in_port)
            if out_port is None:
                return
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            self._install_and_send(datapath, msg, 10, match, actions, in_port)
            return

        
        edge = self.EDGE_SWITCHES.get(dpid) #recupera la congif.dello specifico switch
        if edge is None:
            self.logger.warning("dpid=%s non previsto, scarto", dpid)
            return

        local_ports = edge['local_ports']
        upper_port = edge['upper_port']
        lower_port = edge['lower_port']

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        is_video = self._is_video(pkt)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]


            if out_port in (upper_port, lower_port):
                out_port = upper_port if is_video else lower_port

                if is_video:
                    match = parser.OFPMatch(
                        in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=17, eth_src=src, eth_dst=dst,
                        udp_dst=self.VIDEO_UDP_PORT)
                    priority = 20  # piu' specifica e prioritaria
                else:
                    match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
                    priority = 10
            else:
                # destinazione locale allo stesso switch: consegna diretta
                match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
                priority = 10

            actions = [parser.OFPActionOutput(out_port)]
            self._install_and_send(datapath, msg, priority, match, actions, in_port)
            return

        # --- Destinazione sconosciuta: flood "sicuro", senza ricreare il loop fisico ---
        if in_port in local_ports:
            # da un host locale: agli altri host locali + un SOLO uplink (lower)
            flood_ports = [p for p in local_ports if p != in_port] + [lower_port]
        else:
            # da un uplink: solo verso gli host locali, mai verso l'altro uplink
            flood_ports = list(local_ports)

        actions = [parser.OFPActionOutput(p) for p in flood_ports]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)