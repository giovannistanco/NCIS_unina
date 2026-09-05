# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER,DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet,ipv4,udp, in_proto
from ryu.lib import hub
from ryu.lib.packet import ether_types
import time,random

class datacenter_polisi(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(datacenter_polisi, self).__init__(*args, **kwargs)
        self.mac_to_port = {} # dizionario per la memoria dello switch
        self.datapaths = {} # dizionario per tenere traccia degli switch
        self.port_bytes = {} #dizionari necessari per calcolare la banda usat< visto che ho dei parametri cumulativi
        self.port_times = {}
        self.monitor_thread = hub.spawn(self._monitor) # documentazione ryu per il traffic monitoring(per generare i thread insomma)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER]) #tengo traccia delle connessioni per far sì che il monitor debba interrogare solamente quelle attive
    def _state_change_handler(self, ev):
        datapath = ev.datapath 
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]  #nel caso in cui non siano attive allora le elimino

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto #ofproto mi serve per recuperare le costanti del protocollo
        parser = datapath.ofproto_parser   #parser mi fornisce le strutture standard dei messaggi da mandare
        match = parser.OFPMatch()    #parentesi vuote, catturo tutto il traffico in pratica(ma sto in config_dispatcher,quindi solo di inizializzazione)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]   #come riportato nell'esempio degli appunti uso no_buffer per mandare il messaggio intero
        self.add_flow(datapath, 0, match, actions)  #nota la priorità 0 ,quindi qualsiasi altro gestore con priorità maggiore potrebbe esser eventualmente chiamato

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0): #come negli appunti insomma
        ofproto = datapath.ofproto   #come sopra per usare openflow
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:    #se ha il buffer_id allora lo switch che mi ha mandato il pacchetto lo ha anche memorizzato
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst, hard_timeout=hard_timeout)
        else:   #in questo caso non ha il pacchetto memorizzato 
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def _monitor(self):   #vedi documentazione,monitor che uso per richiedere le statistiche che richiama _request_stats 
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(3) # le richiedo ogni 3 secondi(nella documentazione ogni 10)

    def _request_stats(self, datapath):
        self.logger.debug('Invio richiesta statistiche a elemento di rete: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        #req = parser.OFPFlowStatsRequest(datapath) ometto questo perchè non voglio individuare il singolo host che sta generando troppo traffico
        #datapath.send_msg(req)   #mi interessa fare load balancing e quindi vedere solo il link quanto sia "intasato"
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER) #gestore ricezione statistiche
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body #lista delle stats
        dpid = ev.msg.datapath.id #id dello switch che ci ha mandato le informazioni
        tempo_corr = time.time() #per il calcolo del rate

        for stat in body:
            port_no = stat.port_no
            if port_no == ev.msg.datapath.ofproto.OFPP_LOCAL: #non ci interessa la porta local per lo stack di networking locale
                continue #esci e vai alla prossima

            key = (dpid, port_no)  #esempio switch 2 porta 1
            curr_byte = stat.tx_bytes + stat.rx_bytes   #vedo traffico totale su quel collegamento insomma
            
            if key in self.port_bytes:   #controllo se ho già dati su quella porta di quello switch
                byte_prec = self.port_bytes[key]
                tempo_prec = self.port_times[key]
                
                # trasformo la differenza tra quelli di ora e quelli di prima in bit da byte e poi divido per la differenza di tempo trascorsa dalle due rilevazioni
                period = tempo_corr - tempo_prec
                speed = (curr_byte - byte_prec) * 8 / period
                speedinMbps = speed / 1000000
                
                if speedinMbps > 0.5: #scelgo di riportare tutto il traffico abbastanza rilevante
                    self.logger.info("Switch %s, Porta %s: Throughput = %.2f Mbps", dpid, port_no, speedinMbps)
                    
                   
                    if speedinMbps > 8.0:   #se supera gli 8Mbps su un link per me è grave, la soglia definitiva che ho scelto
                        self.logger.warning("!!! ANOMALIA RILEVATA !!! Switch %s Porta %s supera gli 8 Mbps. Eseguo DROP.", dpid, port_no)
                        self.drop_packet(ev.msg.datapath, port_no)

            self.port_bytes[key] = curr_byte
            self.port_times[key] = tempo_corr

    def drop_packet(self, datapath, port_no):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=port_no,eth_type=0x0800, ip_proto=in_proto.IPPROTO_UDP)   #solo per il traffico della porta in considerazione e udp malevolo, ho un controllo maggiore a livello di flusso
        match_tcp = parser.OFPMatch(in_port=port_no, eth_type=0x0800, ip_proto=in_proto.IPPROTO_TCP)
        actions = [] # uso actions=[] perchè nella documentazione di openflow è riportato che non esistono veri e propri comandi per l'eliminazione e action[] è un modo per farlo capire allo switch
        self.add_flow(datapath, 100, match, actions,hard_timeout=120) # priorità massima e timeout se oer caso individuo l'attacco lo scollego in pratica per 120 secondi


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) #questa parte è stata modificata rispetto al semplice apprendimento degli appunti
    #ho preso una scelta di design per fare in modo che gli host collegati all'ultimo leaf fossero delle macchine dedicate al cloud computing privato
    def _packet_in_handler(self, ev):
        msg = ev.msg #estraggo info del messaggio
        datapath = msg.datapath #estraggo datapath per il parser
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port'] #applico il filtro per la porta

        pkt = packet.Packet(msg.data) #trasformo il dato in un packet per renderlo leggibile
        eth = pkt.get_protocols(ethernet.ethernet)[0] #estraggo l'header ethernet
        if eth.ethertype == ether_types.ETH_TYPE_LLDP: #se è un local discovery lo ignoro, sono pacchetti di mininet che non mi interessano
            return
            
        dst = eth.dst #estraggo sorgente,destinazione e id dell'elemento di rete mittente
        src = eth.src
        dpid = datapath.id 
        
        self.mac_to_port.setdefault(dpid, {}) #come nelle slide, uso setdefault per creare nel caso non esista una riga nel dizionario per memorizzare i mac di quello switch
        self.mac_to_port[dpid][src] = in_port #inserisci il numero porta al mac di questo switch
        #avrei alla fine tanti dizionari insomma per ogni switch che hanno dei mac address come key e porta come value

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4) #sfrutto sdn e il fatto che gli elementi di rete non siano semplici switch, m gestisco il comportamento grazie al controller
        pkt_udp = pkt.get_protocol(udp.udp) # estrae l'header UDP se esiste
        if pkt_ipv4 and pkt_udp:
            udp_dst_port = pkt_udp.dst_port
            if udp_dst_port == 5001:
                self.logger.warning("traffico UDP Porta 5001 rilevato e bloccato") #per simulare il comportamento di un normale firewall di base
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=in_proto.IPPROTO_UDP, udp_dst=5001)
                self.add_flow(datapath, 99, match, []) # elimino il traffico 
                return
        if pkt_ipv4 and datapath.id in [5, 6, 7, 8]:  #sto lavorando a livello 3 e se ho un pacchetto ipv4 che mi arriva dai leaf allora devo gestire gli accessi
            src_ip = pkt_ipv4.src #il mio gateway in realtà sarebbe solo il leaf1 ,ma potrebbero collegarsi anche ad altri leaf eventualmente
            dst_ip = pkt_ipv4.dst
            private_servers = ['10.0.0.7', '10.0.0.8']
            authorized_users = ['10.0.0.12', '10.0.0.13']

            if dst_ip in private_servers and src_ip not in authorized_users:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip) #uso 0x0800 perchè, come nella documentazione di OpenFlow si deve rispettare il prerequisito
                #di match dell'ethernet type e cercando nella documentazione per ip src e dst è il suddetto
                self.add_flow(datapath, 50, match, []) # actions=[] per fare il drop, installo la regola anche per il futuro
                self.logger.warning("ACCESSO NON AUTORIZZATO di %s verso il server privato %s", src_ip, dst_ip)
                return

        edge_ports = {  #visto che in questa topologia ho il leaf 1 che funge anche da gateway devo differenziare la gestione visto che ha le prime 8 porte collegate a degli host
            5: [1, 2, 3, 4, 5, 6, 7], # gateway con 8 pc colegati,il resto solo 2
            6: [1, 2],                
            7: [1, 2],                
            8: [1, 2]                
        }
        
        uplink_ports = {
            5: [8, 9, 10, 11],        # Su Leaf 1, gli Spine partono dalla porta 8
            6: [3, 4, 5, 6],          # Sui restanti Leaf, gli Spine partono dalla porta 3
            7: [3, 4, 5, 6],          
            8: [3, 4, 5, 6]           
        }

        if dst in self.mac_to_port[dpid]: #se ho il destinatario in memoria lo mando alla destinazione scelta
            out_port = self.mac_to_port[dpid][dst] 
        
            if datapath.id in uplink_ports and out_port in uplink_ports[datapath.id]: #ma se il destinatario è uno degli spine e ho un leaf come sorgente
                #faccio load balancing e scelgo uno tra gli spine in modo casuale in modo da non usare sempre lo stesso
                out_port = random.choice(uplink_ports[datapath.id])
                
        else:
            out_port = datapath.ofproto.OFPP_FLOOD #se non ho in memoria lo mando in broadcast
            
            # ma rischio che messaggio in broadcast crei un loop, potrei evitarlo con stp, ma poi mi spegnerebbe molti collegamenti riducendo il mio throughput
            # decido quindi di adottare una soluzione dove decido che se un pacchetto proviene da uno spine non lo rimando a lui,ma solo agli host
            #google in realtà in jupiter usa direttamente bgp e evita i loop con i ttl e il controllo in ibgp
            if datapath.id in edge_ports and in_port in uplink_ports.get(datapath.id, []):
                actions = [parser.OFPActionOutput(p) for p in edge_ports[datapath.id]] #avremo in pratica una lista di action variabile a seconda di quanti pc sono collegati al leaf
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
                datapath.send_msg(out)
                return

        actions = [parser.OFPActionOutput(out_port)] # creo l'azione
        if out_port != datapath.ofproto.OFPP_FLOOD: #nel caso non sia un messaggio broadcast memorizzo la regola altrimenti no
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src) #indico il match dela regola degli indirizzi
            self.add_flow(datapath, 1, match, actions)

        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data #se non ha usato il buffer e mi ha mandato l'intero pacchetto allora lo mando dietro con i dati,altrimenti gli dico solo come inoltrarlo
        else: 
            data=None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data) #sblocco
        datapath.send_msg(out)