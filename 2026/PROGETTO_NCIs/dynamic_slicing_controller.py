from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER # stati dello switch: configurazione, normale, disconnesso
from ryu.controller.handler import set_ev_cls # per associare le funzioni agli eventi
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, in_proto, ipv4, udp
from ryu.lib import hub # per gestire i thread
import time


class DynamicSlicingController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Parametri del dynamic slicing
    POLL = 2.0           # frequenza di polling tra controller e switch
    MIN_DT = 1.5         # tempo minimo tra due misurazioni consecutive per calcolare la lunghezza di banda
    SOGLIA_BASSA = 1.0   # soglia minima per considerare il traffico video scarico e prestare la slice al traffico normale
    SOGLIA_ALTA = 3.0    # soglia massima per considerare il traffico video attivo e riprendere la slice dal traffico normale
    PORTA_VIDEO_INGRESSO = 1   # porta di ingresso del traffico video sullo switch s1

    def __init__(self, *args, **kwargs): 
        super(DynamicSlicingController, self).__init__(*args, **kwargs)
        self.mac_to_port = {} # per mappare gli indirizzi MAC alle porte degli switch
        self.mac_h1 = '00:00:00:00:00:01' 
        self.mac_h2 = '00:00:00:00:00:02'
        self.mac_h3 = '00:00:00:00:00:03'
        self.mac_h4 = '00:00:00:00:00:04'

        # variabili per il dynamic slicing 
        self.datapaths = {}         # per tenere traccia degli switch connessi al controller
        self.be_su_video = False    # indica se il traffico normale (h2<->h4) sta usando la slice video (True) o la slice lenta (False)
        self.rx_prev = None         # memorizza il numero di byte ricevuti dall'ultima misurazione per calcolare la lunghezza di banda
        self.t_prev = time.time()   # memorizza il tempo dell'ultima misurazione per calcolare la lunghezza di banda
        self.monitor_thread = hub.spawn(self._monitor)   # avvia un thread separato per monitorare le statistiche

    # GESTORE DI EVENTI, si attiva quando uno switch cambia stato (connesso, disconnesso)
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev): # creo handler per cambio di stato
        dp = ev.datapath # ottengo l'oggetto datapath dello switch che ha cambiato stato
        if ev.state == MAIN_DISPATCHER: # se lo switch è connesso, lo aggiungo al dizionario dei datapath
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER: # altrimenti lo rimuovo
            self.datapaths.pop(dp.id, None)

    # GESTORE DI EVENTI, si attiva quando uno switch si connette per la prima volta
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()  # match vuoto, quindi cattura tutti i pacchetti (table miss)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)] # invio il pacchetto al controller senza bufferizzarlo
        self.add_flow(datapath, 0, match, actions) # installo la regola di table miss con priorità 0 nello switch

    def add_flow(self, datapath, priority, match, actions, buffer_id=None): # aggiunge regole negli switch
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] 
        if buffer_id:   # creo messaggio di tipo FlowMod per aggiungere la regola nello switch con o senza buffer_id
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else: # qui senza
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    # GESTORE DI EVENTI, si attiva quando uno switch invia un pacchetto al controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev): 
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port'] # porta da cui è arrivato il pacchetto
        dpid = datapath.id

        # DECODIFICA PACCHETTO
        # se il pacchetto non è di tipo Ethernet, lo ignoro
        # senza inviarlo al controller per gestire il traffico in modo più efficiente
        pkt = packet.Packet(msg.data)   
        eth = pkt.get_protocols(ethernet.ethernet)[0] # prendo il primo protocollo Ethernet del pacchetto, che contiene gli indirizzi MAC sorgente e destinazione
        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.ethertype == ether_types.ETH_TYPE_IPV6: # ignoro i pacchetti LLDP e IPv6, che sono usati per il discovery della rete e non sono rilevanti per il routing del traffico normale
            return

        dst = eth.dst # mac destinazione
        src = eth.src # mac sorgente
        self.mac_to_port.setdefault(dpid, {}) # iniizalizzo tabella mac se non esiste 

        # TOPOLOGY SLICING 
        if (src == self.mac_h1 and dst not in [self.mac_h3, 'ff:ff:ff:ff:ff:ff']) or \
           (src == self.mac_h2 and dst not in [self.mac_h4, 'ff:ff:ff:ff:ff:ff']) or \
           (src == self.mac_h3 and dst not in [self.mac_h1, 'ff:ff:ff:ff:ff:ff']) or \
           (src == self.mac_h4 and dst not in [self.mac_h2, 'ff:ff:ff:ff:ff:ff']):
            return

        self.mac_to_port[dpid][src] = in_port # apprendo la porta da cui è arrivato il pacchetto per la sorgente, così da poter rispondere in futuro senza flood

        # ROUTING/BROADCAST
        if dst in self.mac_to_port[dpid]: # se conosco la porta di destinazione
            out_port = self.mac_to_port[dpid][dst] # la uso
        else: # altrimenti faccio flood (broadcast) per trovare la destinazione
            if dpid == 1:
                if src == self.mac_h1: out_port = 2 # se la sorgente è h1, invio verso la porta 2 (Upper Slice)
                elif src == self.mac_h2: out_port = self._porta_best_effort(1)   # se la sorgente è h2, invio verso la porta best effort (2 o 4) a seconda della modalità
                elif src == self.mac_h3: out_port = 1
                elif src == self.mac_h4: out_port = 3
                else: return
            elif dpid == 4: 
                if src == self.mac_h3: out_port = 1
                elif src == self.mac_h4: out_port = self._porta_best_effort(4)  
                elif src == self.mac_h1: out_port = 2
                elif src == self.mac_h2: out_port = 4
                else: return
            elif dpid in [2, 3]: # switch intermediari, inoltro in base alla porta di ingresso
                if in_port == 1: out_port = 2
                elif in_port == 2: out_port = 1
                else: return
            else:
                return

        match = parser.OFPMatch(eth_dst=dst, eth_src=src) # match per la regola da installare nello switch, basata su indirizzi MAC sorgente e destinazione
        priority = 1 # priorità bassa per il traffico normale

        # SERVICE SLICING: video UDP 9999 
        if eth.ethertype == ether_types.ETH_TYPE_IP:  # se il pacchetto è IPv4, controllo se è UDP e destinato alla porta 9999 (video)
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt.proto == in_proto.IPPROTO_UDP:
                udp_pkt = pkt.get_protocol(udp.udp)
                if udp_pkt.dst_port == 9999: # se lo è, imposto priorità alta (100) e sposto tutto il traffico verso 9999
                    match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=9999) 
                    priority = 100
                    if dpid == 1: out_port = 2 
                    elif dpid == 4: out_port = 2

        actions = [parser.OFPActionOutput(out_port)] # forzo l'uscita del pacchetto verso la porta scelta
        if out_port != ofproto.OFPP_FLOOD: # se non è un flood e la porta di destinazione è nota
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, priority, match, actions, msg.buffer_id) # installo la regola nello switch per evitare di inviare il pacchetto al controller in futuro
                return
            else: # se il pacchetto non è bufferizzato, installo la regola senza buffer_id
                self.add_flow(datapath, priority, match, actions)

        data = None 
        if msg.buffer_id == ofproto.OFP_NO_BUFFER: # se il pacchetto non è bufferizzato
            data = msg.data # il controller deve inviare il pacchetto completo allo switch, altrimenti lo switch ha già il pacchetto in memoria e non serve inviarlo di nuovo
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out) 


    # DYNAMIC SLICING  
    def _porta_best_effort(self, dpid): 
        """Porta d'uscita del traffico normale h2<->h4, secondo la modalita'."""
        if self.be_su_video: #se il traffico normale sta usando la slice video, allora la porta di uscita è 2 per s1 e 4 per s4, altrimenti è 4 per s1 e 3 per s4
            return 2 if dpid == 1 else 1    #slice VIDEO  
        else:
            return 4 if dpid == 1 else 3    #slice LENTA  

    def _monitor(self): # thread separato che monitora le statistiche delle porte dello switch s1
        """Sensore: ogni POLL secondi chiedo a s1 le statistiche di PORTA."""
        while True:
            dp = self.datapaths.get(1) # recupero lo switch s1 dal dizionario dei datapath, se è connesso
            if dp: # crea e invia la richiesta di statistiche delle porte di s1
                parser = dp.ofproto_parser
                req = parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY)
                dp.send_msg(req)
            hub.sleep(self.POLL) # mette in pausa il thread per POLL secondi prima di inviare la prossima richiesta

    # GESTORE DI EVENTI, si attiva quando lo switch risponde con le statistiche delle porte
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """Misura il carico VIDEO = byte in ingresso da h1 (porta 1 di s1)."""
        if ev.msg.datapath.id != 1: # se l'id del datapath non è 1 (cioè non è s1), ignoro la risposta
            return
        rx = 0 # inizializzo il contatore dei byte ricevuti dalla porta 1 (traffico video) a 0
        for stat in ev.msg.body: # ciclo su tutte le statistiche delle porte dello switch s1, se trovo la porta 1 (Upper Slice) prendo il numero di byte ricevuti
            if stat.port_no == self.PORTA_VIDEO_INGRESSO:
                rx = stat.rx_bytes

        now = time.time() # tempo corrente in secondi, per calcolare la lunghezza di banda
        if self.rx_prev is None: # se è la prima volta che ricevo le statistiche            
            self.rx_prev = rx # salvo i dati correnti per il prossimo calcolo della lunghezza di banda
            self.t_prev = now
            return

        dt = now - self.t_prev # calcolo il tempo trascorso dall'ultima misurazione, se è troppo breve non calcolo la lunghezza di banda per evitare valori instabili
        if dt < self.MIN_DT:                   
            return

        mbps = (rx - self.rx_prev) * 8.0 / (1000000 * dt) # calcolo la lunghezza di banda in Mbps, 8.0 per convertire da byte a bit, 1000000 per convertire da bit a megabit
        self.rx_prev = rx # salvo i dati correnti per il prossimo calcolo della lunghezza di banda
        self.t_prev = now
        self._decidi(max(0.0, mbps))

    # LOGICA DI DECISIONE DEL DYNAMIC SLICING
    def _decidi(self, video_mbps): 
        """Decide se prestare o riprendere la slice video (con isteresi)."""
        if not self.be_su_video and video_mbps < self.SOGLIA_BASSA: # se il best-effort non sta usando la slice video e il traffico video è scarico, allora presto la slice video al traffico normale
            self.be_su_video = True
            self._programma_best_effort()
            self.logger.info("[DYNAMIC] Video scarico (%.2f Mbps) -> presto la slice VIDEO al traffico normale", video_mbps)
        elif self.be_su_video and video_mbps > self.SOGLIA_ALTA: # altrimenti applico i cambiamenti di slice e riprendo la slice video dal traffico normale
            self.be_su_video = False
            self._programma_best_effort()
            self.logger.info("[DYNAMIC] Video attivo (%.2f Mbps) -> il traffico normale torna sulla slice LENTA", video_mbps)

    def _programma_best_effort(self): # per ottenere la porta di uscita del traffico normale h2<->h4
        """Riscrive le regole del traffico h2<->h4 sul path scelto.
        Prima cancella le vecchie regole (su tutti gli switch) cosi' il
        cambio di slice ha effetto subito, poi installa l'instradamento nuovo."""
        p1 = self._porta_best_effort(1)   # direzione h2->h4 (decisa da s1) 
        p4 = self._porta_best_effort(4)   # direzione h4->h2 (decisa da s4)
        for dp in self.datapaths.values(): # cancello le regole del traffico normale h2<->h4 su tutti gli switch, così da non avere conflitti con le nuove regole
            self._cancella_be(dp, self.mac_h2, self.mac_h4)
            self._cancella_be(dp, self.mac_h4, self.mac_h2) 
        s1 = self.datapaths.get(1) # inserisco le nuove regole del traffico normale h2<->h4 solo su s1 e s4, che sono gli switch che gestiscono il traffico normale
        s4 = self.datapaths.get(4)
        if s1:
            self._regola_be(s1, self.mac_h2, self.mac_h4, p1) # instrado il traffico normale h2->h4 verso la porta scelta da s1
        if s4:
            self._regola_be(s4, self.mac_h4, self.mac_h2, p4) # instrado il traffico normale h4->h2 verso la porta scelta da s4


    def _cancella_be(self, datapath, src, dst): 
        """Cancella eventuali flow del traffico h2<->h4 gia' presenti."""
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=src, eth_dst=dst)
        mod = parser.OFPFlowMod(datapath=datapath, command=ofp.OFPFC_DELETE, # prendo tutte le porte e tutti i gruppi che fanno match con src e dst, così da cancellare eventuali regole già presenti per il traffico normale h2<->h4
                                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)


    def _regola_be(self, datapath, src, dst, out_port): # installo una regola a priorità 50 per instradare il traffico normale h2<->h4 verso la porta scelta, così da avere un instradamento dinamico del traffico normale in base al carico del traffico video
        """Flow a priorita' 50: sopra al normale (1) ma sotto al video (100)."""
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=src, eth_dst=dst)
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, 50, match, actions)
