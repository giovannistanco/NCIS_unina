import os
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp, ether_types, in_proto

MODE = os.environ.get('SLICING_MODE', 'topology').lower() # Cambio modalità tramite variabile d'ambiente

VIDEO_UDP_PORT = 9999  # Porta per il traffico video

SLICE_OF_MAC = {    # Mappa dei MAC address
    '00:00:00:00:00:01': 'UPPER',   # h1
    '00:00:00:00:00:03': 'UPPER',   # h3
    '00:00:00:00:00:02': 'LOWER',   # h2
    '00:00:00:00:00:04': 'LOWER',   # h4
}

HOST_LOCATION = {                 # Locazione host definita da MAC : (dpid switch, porta)
    '00:00:00:00:00:01': (1, 1),  # h1
    '00:00:00:00:00:02': (1, 2),  # h2
    '00:00:00:00:00:03': (4, 1),  # h3
    '00:00:00:00:00:04': (4, 2),  # h4
}

SLICE_PATH = {  # Percorso per ciascun slice 
    'UPPER': {
        1: {1: 3, 3: 1},      # s1 tra h1 ed s2
        2: {1: 2, 2: 1},      # s2 tra s1 ed s4
        4: {1: 3, 3: 1},      # s4 tra h3 ed s2
    },
    'LOWER': {
        1: {2: 4, 4: 2},      # s1 tra h2 ed s3
        3: {1: 2, 2: 1},      # s3 tra s1 ed s4
        4: {2: 4, 4: 2},      # s4 tra h4 ed s3
    },
}

EDGE_UPLINK = {                   # Da edge verso core
    'UPPER': {1: 3, 4: 3},        # via s2
    'LOWER': {1: 4, 4: 4},        # via s3
}

TRANSIT = {                       # Istradamento core switch
    2: {1: 2, 2: 1},              # s2 (UPPER)
    3: {1: 2, 2: 1},              # s3 (LOWER)
}

BCAST_TREE = {                    # Disabilitiamo collegamento S2 per evitare ciclo (Broadcast storm)
    1: [1, 2, 4],                 # s1: h1, h2, s3
    3: [1, 2],                    # s3: s1, s4
    4: [1, 2, 4],                 # s4: h3, h4, s3
}

IDLE_TIMEOUT = 30                 # timeout di regole non utilizzate per 30s
PRIO_VIDEO = 20                   # regole video 
PRIO_FORWARD = 10                 # regole di inoltro generiche
PRIO_DROP = 5                     # regole di scarto
PRIO_MISS = 0                     # regola non presente

class NetworkSlicing(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):         # costruttore di inizializzazione a cui passiamo oggetto identita', tupla e dizionario
        super(NetworkSlicing, self).__init__(*args, **kwargs) 
        self.mac_to_port = {}                    # dpid -> {mac: porta}, diagnostica
        self.recent_flows = {}                   # (dpid, prio, match) -> istante
        if MODE not in ('topology', 'service'):
            raise ValueError("SLICING_MODE deve essere 'topology' o 'service'")
        self.logger.info('=== MODALITA\': %s ===', MODE.upper()) 

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) 
    def switch_features_handler(self, ev):       # funzione di configurazione switch
        datapath = ev.msg.datapath               
        parser = datapath.ofproto_parser        
        ofproto = datapath.ofproto               
        match = parser.OFPMatch()                # table-miss: tutto al controller 
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]  
        self._add_flow(datapath, PRIO_MISS, match, actions)
        self.logger.info('[SWITCH] s%s connesso', datapath.id)

    def _add_flow(self, datapath, priority, match, actions, idle=0, buffer_id=None):  # funzione di servizio per scrivere una regola (burocraticamente) nella memoria dello switch
        parser = datapath.ofproto_parser   
        ofproto = datapath.ofproto        
        # lista di azioni vuota => nessuna istruzione => il pacchetto e' scartato
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] if actions else []  
        kwargs = dict(datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout=idle)
        if buffer_id is not None:  #lo switch trattiene il corpo del pacchetto e manda solo l id al controller per non sprecare banda di rete
            kwargs['buffer_id'] = buffer_id      # regola + inoltro in un messaggio
        mod = parser.OFPFlowMod(**kwargs)       
        datapath.send_msg(mod)                   

    def _send_packet(self, msg, actions):       # funzione per il recupero del pacchetto in "ostaggio"
        datapath = msg.datapath                 
        parser = datapath.ofproto_parser         
        ofproto = datapath.ofproto              
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:   # verifica se lo switch non ha memorizzato il pacchetto
            data = msg.data                     # salva il corpo del pacchetto all interno di data perche non ha buffer
        else:
            data = None                         # altrimenti salva None => Ha buffer libero lo salva in memoria 
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match['in_port'], actions=actions, data=data)
        datapath.send_msg(out)                 
 
    def _already_installed(self, key):         # filtro antispam per evitare di far inoltrare pacchetti successivi (con richieste identiche) dallo switch (ancora non ci sono regole per gestirli)
        now = time.time()                      
        last = self.recent_flows.get(key)      # recupera ultimo istante in cui e' stata registrata la regola o None 
        if last is not None and now - last < IDLE_TIMEOUT:         # controllo se la regola e' presente e se e' ancora valida 
            return True                        
        self.recent_flows[key] = now           # aggiorna il timestamp 
        if len(self.recent_flows) > 1000:      # pulizia delle voci scadute
            flows_puliti = {}                  
            for k, t in self.recent_flows.items():   
                if now - t < IDLE_TIMEOUT:      
                    flows_puliti[k] = t         
            self.recent_flows = flows_puliti   
        return False                           # la regola o ha superato il timeout o non e' presente

    @staticmethod                              
    def _is_bum(mac):                          # funzione controllo MAC address Unicast o Multi/Broad-cast
        return bool(int(mac.split(':')[0], 16) & 1)  #ritorna un booleano per il controllo valutando la prima ottava e lo converte in esadecimale comparandolo con una AND bit a bit (dispari o pari)
                                               # se dispari il risultato dell operazione e' 1 (return true-mac broad/multicast), 0 se pari (return false-mac unicast)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)         
    def packet_in_handler(self, ev):                                  # funzione per ogni pacchetto senza che arriva al singolo switch
        msg = ev.msg                                                  
        datapath = msg.datapath                                       # estrae dal messaggio il mittente 
        parser = datapath.ofproto_parser                             
        dpid = datapath.id                                            
        in_port = msg.match['in_port']                                # fa match per cercare la porta da cui e' entrato il pacchetto 

        pkt = packet.Packet(msg.data)                                 # prende i dati dal pacchetto divisi gia in strati logici 
        eth = pkt.get_protocol(ethernet.ethernet)                     # prende la parte relativa allo strato ethernet 
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP: # scarto il rumore => eth is None (pacchetto malformato) o eth.ehtertype (traffico non utente)
            return                                                    

        src = eth.src                                                 
        dst = eth.dst                                                 

        if dpid not in self.mac_to_port:                              # se il controller non aveva mai ricevuto pacchetti da questo switch
            self.mac_to_port[dpid] = {}                               # creo un nuovo dizionario annidato
        self.mac_to_port[dpid][src] = in_port                         # registro la posizione: per lo switch dpid, il mac src e' collegato alla porta in_port

        if src not in HOST_LOCATION:                                  # MAC non trovato nella tabella HOST, dispositivo sconosciuto
            match = parser.OFPMatch(eth_src=src)                      # crea condizione di match
            if not self._already_installed((dpid, PRIO_DROP, str(match))):           # controllo se ho gia questo MAC su questo switch negli ultimi 30s, passo la tupla (dpid, Prio_Drop(che tipo di regola abbiamo installato (scarto in questo caso)), trasformo match in stringa)
                self.logger.info('[DROP] s%s: sorgente sconosciuta %s', dpid, src)   
                self._add_flow(datapath, PRIO_DROP, match, [], idle=IDLE_TIMEOUT)    # installo regola 

        if MODE == 'topology':                                        # dopo i vari controlli, il controller ha pacchetto leggittimo e deve scegliere come operare se service o topology
            self._handle_topology(msg, pkt, eth, dpid, in_port, src, dst)
        else:
            self._handle_service(msg, pkt, eth, dpid, in_port, src, dst)

    def _handle_topology(self, msg, pkt, eth, dpid, in_port, src, dst):   # Topology
        datapath = msg.datapath                                           
        parser = datapath.ofproto_parser                                 

        slice_name = SLICE_OF_MAC.get(src)                                # a quale gruppo appartiene mac src? UPPER o LOWER
        if slice_name is None:                                            # se il mac non appartiene a nessuno slice
            return                                                 
 
        bum = self._is_bum(dst)                                           # true se broad/multicast, false se unicast in variabile bum

        # Isolamento: unicast verso uno slice diverso -> scarto
        if not bum and SLICE_OF_MAC.get(dst) != slice_name:                        # se messaggio e' unicast E mac destinazione appartiene ad un gruppo diverso dal mittente
            match = parser.OFPMatch(eth_src=src, eth_dst=dst)                      # forma la regola specifica in variabile match
            if not self._already_installed((dpid, PRIO_DROP, str(match))):         # controllo se la regola esiste gia' 
                self.logger.info('[DROP] s%s: %s (%s) -> %s : slice diversi', dpid, src, slice_name, dst)               
                self._add_flow(datapath, PRIO_DROP, match, [], idle=IDLE_TIMEOUT)  # aggiungiamo la regola  
            return                                                                 
                                                                                   # il mess puo ancora essere sia unicast sia broad/multi
        out_port = SLICE_PATH[slice_name].get(dpid, {}).get(in_port)               # vede mappa di "routing" con UPPER/LOWER, switch id e prende in ingresso la porta in_port per vedere la porta d'uscita
        if out_port is None:                                                       
            return                                                                 # porta fuori dal percorso, esci 

        actions = [parser.OFPActionOutput(out_port)]                               

        if bum:                                   # broadcast: inoltro, nessuna regola
            self._send_packet(msg, actions)       
            return                               

        match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)         # regola per unicast per lo stesso slice
        if self._already_installed((dpid, PRIO_FORWARD, str(match))):              
            self._send_packet(msg, actions)                                        # gia' installata, solo inoltro
            return                                                                 

        self.logger.info('[FLOW] s%s [%s] %s -> %s : porta %s -> %s', dpid, slice_name, src, dst, in_port, out_port)  
                                                                                   # controllo buffer switch
        if msg.buffer_id != datapath.ofproto.OFP_NO_BUFFER:                        # true se buffer id del messaggio nella memoria dello switch e' diverso da OFP_NO_BUFFER, quindi lo switch ha buffer
            self._add_flow(datapath, PRIO_FORWARD, match, actions, idle=IDLE_TIMEOUT, buffer_id=msg.buffer_id)        # il controller aggiunge la regola in modo che (tramite OpenFlow) lo switch salvi la regola e inoltri il pacchetto in un colpo solo (dato che gli fornisco anche l id del mess nel buffer), senza separare le operazioni
        else:                                                                      # switch non ha memoria 
            self._add_flow(datapath, PRIO_FORWARD, match, actions, idle=IDLE_TIMEOUT)                                 
            self._send_packet(msg, actions)                                        

    def _handle_service(self, msg, pkt, eth, dpid, in_port, src, dst):             # Service
        datapath = msg.datapath                                                  
        parser = datapath.ofproto_parser                                           

        # --- Broadcast/multicast: flooding sull'albero fissato 
        if self._is_bum(dst):                                                      # se multi/broadcast entra
            ports = []                                                             # lista per salvare le porte definitive
            porte_sicure = BCAST_TREE.get(dpid, [])                                # Quali sono tutte le porte sicure per questo switch? 
            for p in porte_sicure:                                                 
                if p != in_port:                                                   # se la porta e' diversa da quella di ingresso
                    ports.append(p)                                                    
            if ports:                                                              # se la lista ports non e' vuota
                azioni = []                                                        # lista vuota azioni
                for p in ports:                                                    
                    comando = parser.OFPActionOutput(p)                            
                    azioni.append(comando)                                         # inserisco il comando nella lista azioni
                self._send_packet(msg, azioni)                                     # consegno il pacchetto allo switch dicendo di eseguire tutte le azioni nella lista
            return                                                                

        if dst not in HOST_LOCATION:                                               # se il mac destinazione non e' nella lista
            return                                                                 

        # Classificazione del traffico 
        is_video = False                                                           # partiamo dal presupposto che il traffico non sia video
        udp_hdr = None                                                             # variabile per analizzare le porte
        ip4 = pkt.get_protocol(ipv4.ipv4)                                          # tiriamo fuori le info dallo strato IPv4 lv3
        if ip4 is not None and ip4.proto == in_proto.IPPROTO_UDP:                  # ip4 e' valido? il traffico e' udp?
            udp_hdr = pkt.get_protocol(udp.udp)                                    # ip valido e traffico video = prelevo informazioni dallo strato UDP lv4
            if udp_hdr is not None and udp_hdr.dst_port == VIDEO_UDP_PORT:         # controllo se l header udp e' presente e se sto parlando con la porta designata allo streaming video
                is_video = True                                                    # setto is_video true
        slice_name = 'UPPER' if is_video else 'LOWER'                              # se is_video true slice_name e' UPPER altrimenti LOWER

        # Calcolo della porta di uscita 
        dst_dpid, dst_port = HOST_LOCATION[dst]                                    # recupero a quale switch e quale porta devo usare 
        if dpid == dst_dpid:                                                       # se il destinatario e' su questo switch
            out_port = dst_port                                                    # porta uscita = porta destinazione
        elif dpid in EDGE_UPLINK[slice_name]:                                      # se il pid e' su switch edge prendi percorso dello slice giusto
            out_port = EDGE_UPLINK[slice_name][dpid]                               # porta uscita = porta di destinazione nella tabella dei router edge per lo switch con il dpid corrente
        elif dpid in TRANSIT:                                                      # se il pid e' su switch di transito 
            out_port = TRANSIT[dpid].get(in_port)                                  # porta uscita = porta di uscita correlata ad in_port usato come chiave di ricerca
        else:                                                                      # switch ne destinazione finale ne di accesso ne di transito 
            out_port = None                                                        # nessuna porta assegnata

        if out_port is None:                                                       # se nessuna porta assegnata
            return                                                                 

        actions = [parser.OFPActionOutput(out_port)]                               

        # Costruzione del match 
        if ip4 is None:                                                            # traffico non ipv4 
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst, eth_type=eth.ethertype)     # cerca pacchetti che entrano in questa porta con questi MAC e con questo esatto EtherType (es. ARP)
            priority = PRIO_FORWARD                                                # normale priorita' assegnata
        elif ip4.proto == in_proto.IPPROTO_UDP:                                    # se UDP
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst, eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_UDP, udp_dst=udp_hdr.dst_port)  
            priority = PRIO_VIDEO if is_video else PRIO_FORWARD                    # se traffico video - PRIO VIDEO altrimenti PRIO NORMALE 
        else:                                                                      # il traffico e' IP ma non UDP
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst, eth_type=ether_types.ETH_TYPE_IP, ip_proto=ip4.proto)   
            priority = PRIO_FORWARD                                                # assegna normale prio

        if self._already_installed((dpid, priority, str(match))):                  # se la regola e' gia presente (specificando la priorita ora)
            self._send_packet(msg, actions)                                        # gia' installata: solo inoltro il pacchetto bloccato
            return                                                            

        self.logger.info('[FLOW] s%s [%s%s] %s -> %s : porta %s -> %s', dpid, slice_name, ' VIDEO' if is_video else '', src, dst, in_port, out_port)   

        if msg.buffer_id != datapath.ofproto.OFP_NO_BUFFER:                        # ho buffer disponibile 
            self._add_flow(datapath, priority, match, actions, idle=IDLE_TIMEOUT, buffer_id=msg.buffer_id)  #passo anche buff id per inoltro del pacchetto oltre che la regola
        else:                                                                      # non ho buffer disponibile
            self._add_flow(datapath, priority, match, actions, idle=IDLE_TIMEOUT)  # istruisco lo switch con la nuova regola 
            self._send_packet(msg, actions)                                        # gli dico di mandare manualmente il pacchetto che non aveva conservato 