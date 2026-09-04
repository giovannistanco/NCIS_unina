#!/usr/bin/env python3
"""
Ryu SDN Controller per Difesa DDoS Dinamica e Anti Over-Blocking.
- OpenFlow 1.3
- Monitoraggio RX/TX su tutte le porte
- Rilevamento flussi anomali e mitigazione mirata per IP
- Unblocking automatico temporizzato
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
from ryu.lib import hub
import time

class DefenseController(app_manager.RyuApp):                               
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]                              

    def __init__(self, *args, **kwargs):      

        super().__init__(*args, **kwargs)    
               
        self.mac_to_port = {} 
        self.datapaths = {} 
        self.port_stats = {}
        
        # Parametri Operativi
        self.MONITOR_INTERVAL = 2       
        self.THRESHOLD_MBPS = 4.0                                  
        self.THRESHOLD_PPS = 650.0     
        self.BLOCKED_TIMEOUT = 20       
        self.blocked_ips = set()       
        
        # Mapping IP/Porta appresi dinamicamente
        self.ip_to_location = {} 
        
        self.monitor_thread = hub.spawn(self._monitor) # generi un thread che esegue la funzione self._monitor in loop continuo. 


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    #Avviata la topologia su Mininet, gli switch si collegano per la prima volta al controller Ryu inviando un messaggio iniziale di presentazione
    def switch_features_handler(self, ev):                                                   
        datapath = ev.msg.datapath                                                          
        ofproto = datapath.ofproto  #l'elenco delle costanti/numeri standard dove ogni codice corrisponde a una cosa precisa (una porta speciale, un'azione, una priorità).                  
        parser = datapath.ofproto_parser  #traduce le istruzioni nel formato comprensibile allo switch                                           
        self.datapaths[datapath.id] = datapath                                               

        #TABLE-MISS                                                                           
        match = parser.OFPMatch()                                                           
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]  
        self.add_flow(datapath, priority=0, match=match, actions=actions)                    
        self.logger.info("Switch registrato: DPID=%016x", datapath.id)                       

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] 
       
        if buffer_id: # se uno switch ha già un pacchetto nel buffer, applica la regola anche a lui
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, 
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
            
        datapath.send_msg(mod) #manda il messaggio allo switch 

    #Effettua il drop di tutto il traffico che proviene da un indirizzo IP specifico ritenuto malevolo
    def add_drop_flow(self, datapath, src_ip, hard_timeout):                                               
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)                                     
        self.add_flow(datapath, priority=100, match=match, actions=[], hard_timeout=hard_timeout)                       
        self.logger.info(">>> [MITIGAZIONE ATTIVA] Flow DROP installato su DPID=%016x per IP=%s (Durata: %ds)",
                         datapath.id, src_ip, hard_timeout)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    #il controller inietta la regola di inoltrare i pacchetti verso la porta di uscita
    def packet_in_handler(self, ev):
        msg = ev.msg 
        datapath = msg.datapath
        ofproto = datapath.ofproto 
        parser = datapath.ofproto_parser 
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data) 
        eth = pkt.get_protocols(ethernet.ethernet)[0] 

        #se si tratta di un pacchetto LLDP, usato solo per scoprire la topologia della rete tra switch, lo ignora
        if eth.ethertype == ether_types.ETH_TYPE_LLDP: 
            return

        # Traccia la sorgente IP e la sua posizione di rete
        ip_pkt = pkt.get_protocol(ipv4.ipv4) 
        if ip_pkt: 
            self.ip_to_location[ip_pkt.src] = (datapath.id, in_port) #associa l'ip del mittente all'id dello switch e alla sua porta
        
        dst = eth.dst 
        src = eth.src 
        dpid = datapath.id 
        self.mac_to_port.setdefault(dpid, {}) 
        self.mac_to_port[dpid][src] = in_port 
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD) 
        actions = [parser.OFPActionOutput(out_port)] 

        if out_port != ofproto.OFPP_FLOOD: #Se la destinazione è nota (quindi NON è flood)
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src) 
            if msg.buffer_id != ofproto.OFP_NO_BUFFER: #se quel determinato pacchetto, lo switch non sapendo che fare lo ha "parcheggiato" nel suo buffer 
                self.add_flow(datapath, priority=1, match=match, actions=actions, #aggiungi la regola nella flow table
                              buffer_id=msg.buffer_id, idle_timeout=10)
                return
            else: #altrimenti, se lo switch non aveva parcheggiato il pacco nel buffer, aggiungi la regola direttamente
                self.add_flow(datapath, priority=1, match=match, actions=actions, idle_timeout=10) 

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER: #Se lo switch non ha tenuto nulla nella RAM e ha spedito l'intero pacchetto al controller, quest'ultimo gli deve
                                                   # riinviare data (il contenuto del pacchetto) 
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, 
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out) 

    def _monitor(self): 
        while True: #Crea un ciclo infinito
            for dp in list(self.datapaths.values()): 
                self._request_stats(dp) 
            hub.sleep(self.MONITOR_INTERVAL) #mette in pausa il thread per un intervallo di tempo pari a MONITOR_INTERVAL

    def _request_stats(self, datapath):                                          
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY) 
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    #Viene eseguita quando arriva la risposta con le statistiche dallo switch.
    def port_stats_reply_handler(self, ev): 
        body = ev.msg.body 
        dpid = ev.msg.datapath.id 
        current_time = time.time()
        
        self.port_stats.setdefault(dpid, {}) 

        for stat in body: #per ogni porta presente nel report
            port_no = stat.port_no
            if port_no > ofproto_v1_3.OFPP_MAX: 
                continue 

            total_bytes = max(stat.rx_bytes, stat.tx_bytes) #Prende il valore più alto tra byte ricevuti (rx_bytes) e trasmessi (tx_bytes) per rilevare se ci sono picchi sia in ingresso che in uscita.
            total_packets = max(stat.rx_packets, stat.tx_packets) #Prende il valore più alto dei pacchetti (RX/TX)

            prev = self.port_stats[dpid].get(port_no) 

            if prev:
                delta_bytes = total_bytes - prev['bytes']
                delta_packets = total_packets - prev['packets']                                                                          
                delta_time = current_time - prev['time']
                
                if delta_time > 0:
                    throughput_mbps = (delta_bytes * 8.0) / (delta_time * 1000000.0)  #converte i byte in Megabit al secondo
                    pps = delta_packets / delta_time # Calcola i pacchetti al secondo
                    
                    
                    if throughput_mbps > self.THRESHOLD_MBPS and pps > self.THRESHOLD_PPS:
                        self.logger.warning("! [ALLARME TRAFFICO] Switch=%016x Porta=%d Throughput=%.2f Mbps | PPS=%.1f",
                                            dpid, port_no, throughput_mbps, pps)

                        # 1. Ricerca dinamica dell'IP collegato a questa porta congestionata
                        attacker_ip = None
                        for ip, location in self.ip_to_location.items():   
                            if location == (dpid, port_no):               
                                attacker_ip = ip
                                break

                        # 2. Se l'IP è stato individuato e non è nella lista dei bloccati
                        if attacker_ip and attacker_ip not in self.blocked_ips:
                            self.blocked_ips.add(attacker_ip) 
                            for dp in self.datapaths.values():
                                self.add_drop_flow(dp, attacker_ip, self.BLOCKED_TIMEOUT) 
                            hub.spawn_after(self.BLOCKED_TIMEOUT, self._unblock_ip, attacker_ip) 

            # Salva il numero di pacchetti per il ciclo successivo
            self.port_stats[dpid][port_no] = {'bytes': total_bytes, 'packets': total_packets, 'time': current_time}

    def _unblock_ip(self, ip):
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            self.logger.info("<<< [UNBLOCK] Periodo di mitigazione scaduto per IP=%s. Ripristino traffico.", ip)