#!/usr/bin/env python3
"""
Controller Ryu "baseline": un semplice learning switch L2, SENZA rilevamento né
mitigazione del DoS.

A cosa serve: la traccia (sezione "Integration & Execution") chiede di mostrare
il comportamento della rete PRIMA e DOPO l'introduzione della logica di
sicurezza. Questo file è il "prima": lo si avvia, si genera il traffico
d'attacco e si osserva la degradazione delle prestazioni per gli host
legittimi (packet loss, latenza, throughput). Poi si ripete lo stesso
esperimento con controller.py (che include detection e mitigazione) per
mostrare il miglioramento.

Avvio:
    ryu-manager baseline_controller.py
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types

PRIORITY_TABLE_MISS = 0
PRIORITY_FORWARDING = 1

class BaselineLearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(BaselineLearningSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {} #tabella indirizzi MAC

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """ Metodo per configurare uno switch appena connesso """
        datapath = ev.msg.datapath
        ofproto, parser = datapath.ofproto, datapath.ofproto_parser
        match = parser.OFPMatch() #criterio di match che cattura qualsiasi pacchetto
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)] # definisce l'azione "invia pacchetti a controller, senza memorizzare nel buffer"
        self._add_flow(datapath, PRIORITY_TABLE_MISS, match, actions) #creazione regola di table miss

    @staticmethod
    def _add_flow(datapath, priority, match, actions, buffer_id=None):
        """ Metodo per aggiungere una regola nello switch """
        ofproto, parser = datapath.ofproto, datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] #crea un'istruzione a partire dalle azioni indicate dal controller
        
        #creazione della regola
        if buffer_id: #buffer_id indica se il pacchetto era memorizzato nel buffer dello switch
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                     priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                     match=match, instructions=inst)
        datapath.send_msg(mod) #invio della regola allo switch

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """ Metodo per gestire un pacchetto in arrivo da uno switch """

        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id #estrazione dell'id dello switch
        ofproto, parser = datapath.ofproto, datapath.ofproto_parser
        in_port = msg.match['in_port'] #lettura della porta d'ingresso da cui è arrivato il pacchetto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP: #se pacchetto LLDP (usato per scoprire la topologia) è inutile andare avanti, mi fermo
            return

        dst, src = eth.dst, eth.src # estrazione di MAC sorgente e destinazione
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port #creazione dell'associazione MAC_SRC -> in_port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD) #cerca porta di output fra quelle conosciute, altrimenti mette FLOOD
        actions = [parser.OFPActionOutput(out_port)]

        #se la porta è diversa da FLOOD, crea una regola che associa alla porta di uscita il flusso del pacchetto arrivato,
        #in modo che il prossimo pacchetto di questo flusso viene inviato direttamente ad out_port, senza passare per il controller
        #La regola viene creata solo se out_port != ofproto.OFPP_FLOOD, cioè se il controller conosce la porta associata al MAC di uscita 
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src) #flusso identificato da porta d'ingresso, MAC sorgente e MAC destinazione
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self._add_flow(datapath, PRIORITY_FORWARDING, match, actions, msg.buffer_id)
                return
            else:
                self._add_flow(datapath, PRIORITY_FORWARDING, match, actions)

        #invio del pacchetto verso la destinazione
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
