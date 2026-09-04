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
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


from ryu.lib import hub


from ryu.lib.packet import arp


import time




class Detector(app_manager.RyuApp):
    """Learning switch OpenFlow 1.3 con monitor delle statistiche.

    Reagisce a tre eventi (features reply, packet_in, flow stats reply)
    e [6] esegue in parallelo un ciclo di polling. Stato in RAM:
    mac_to_port (tabella di apprendimento) e datapaths (switch connessi).
    """

    # Versione di OpenFlow negoziata con lo switch.
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

   #Soglia per rilevare una scansione
    ARP_MIN = 20
   
    FANOUT_MIN = 5

    #Durata di HARD_TIMEOUT della regola di drop
    CONTAIN_SEC = 30

    # [8]Priorita' della regola di drop.
    DROP_PRIO = 100

    def __init__(self, *args, **kwargs):
        """Inizializza le strutture di stato e [6] avvia il monitor."""
        super(Detector, self).__init__(*args, **kwargs)

        # Tabella di apprendimento, una per switch: {dpid: {mac: porta}}.
        self.mac_to_port = {}

        #[7] Dizionario che contiene la somma (cumulata) dei packet_count
        #Di un flow {(dpid, in_port, eth_src, eth_dst): packet_count}
        self.flow_prev = {}

        #[7] Dizionario che si azzera per ogni ciclo di _monitor
        #{eth_src: {'arp': int, 'dsts': set(), 'pkts': int}}.
        self.window = {}

        
        # [8] Dizionario in cui inserire gli host contenuti, con scadenza: {eth_src: t_scadenza}.
        # Per ogni host, la chiave è il MAC e t_scadenza è calcolato come time.time() + CONTAIN_SEC.
        self.flagged = {}

        # [6] Creiamo un dizionario con gli Switch connessi: {dpid: oggetto datapath}
        # Serve nel polling.
        self.datapaths = {}

        # [6] Avvia un thread a cui passi la funzione _monitor
        # serve perchè il polling avviene di continuo
        self.monitor_thread = hub.spawn(self._monitor)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Installa la table-miss entry alla connessione dello switch.

        Chiamata all'arrivo del Features Reply, una volta per switch,
        durante l'handshake (lo SWITCH si collega al controller tramite
        connessione TCP, a questo punto il controller invia la F.request). 
        Usa ev.msg.datapath e il suo ofproto_parser.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Campo MATCH vuoto: fa match su qualunque pacchetto. Con
        # priority=0 perde contro ogni altra entry.
        match = parser.OFPMatch()

        # Invia al controller il pacchetto INTERO. OFPCML_NO_BUFFER vale
        # 65535, il numero che si legge come CONTROLLER:65535.
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)

        # [6] Primo punto in cui il controller ha il riferimento allo
        # switch: lo registra per poterlo interrogare in seguito.
        self.datapaths[datapath.id] = datapath

    def add_flow(self, datapath, priority, match, actions, buffer_id=None,
                 hard_timeout=0, idle_timeout=0):
        """Costruisce un messaggio FlowMod e lo invia allo switch.

        Alla fine sarà chiamata da _contain per installare la regola di drop con HARD_TIMEOUT.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # In OF 1.3 una flow entry contiene istruzioni, non azioni
        # dirette. OFPIT_APPLY_ACTIONS = applica subito.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        # costruisco il messaggio FlowMod 
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,
                                    hard_timeout=hard_timeout,
                                    idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    hard_timeout=hard_timeout,
                                    idle_timeout=idle_timeout)

        # Invia il messaggio allo switch: la regola viene installata.
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Impara il MAC sorgente, inoltra il pacchetto, installa la regola.

        Chiamata a ogni packet_in, cioe' a ogni pacchetto che cade sulla
        table-miss. Usa ev.msg (datapath, match, buffer_id, data) e la
        classe Packet per estrarre l'header Ethernet.
        """
        # Pacchetto troncato: indica un miss_send_length troppo basso.
        # Con OFPCML_NO_BUFFER non accade.
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        # Estrae i campi principali del messaggio packet_in. 
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        # Estrae il solo header Ethernet.
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Unico filtro presente: scarta LLDP, nient'altro.
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst

        #[OG] MAC source preso da header ethernet
        src = eth.src

        # identificatore dello switch
        dpid = datapath.id

        # [7] Dal frame eth prendiamo il pacchetto ARP
        pkt_arp = pkt.get_protocol(arp.arp)


        # Crea il sotto-dizionario di questo switch se e' il primo
        # pacchetto che ne arriva. Non apprende nulla.
        self.mac_to_port.setdefault(dpid, {})

        

        # [7] Crea il dizionario che tiene traccia PER HOST (identificato da src)
        # di arp, dsts (quali), pkts
        self.window.setdefault(src, {'arp': 0, 'dsts': set(), 'pkts': 0})

        # [7] Se il pkt ricevuto, è una ARP_REQ, ha dst=ff e, ha un header ARP
        # aggiungi 1 al conteggio di quell'host
        if (pkt_arp is not None
                and pkt_arp.opcode == arp.ARP_REQUEST
                and dst == 'ff:ff:ff:ff:ff:ff'):
            self.window[src]['arp'] += 1

        #[7] Inoltre, se dst != 33:33 (rumore ipv6) aggiugni dst a dst
        if dst != 'ff:ff:ff:ff:ff:ff' and not dst.startswith('33:33'):
            self.window[src]['dsts'].add(dst)



        # Per ogni pkt_in ricevuto, il controller stampa una riga di log
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # [OG] Apprendimento: associa il MAC SORGENTE alla porta d'ingresso.
        # Unico punto in cui mac_to_port si popola.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Se la destinazione e' sconosciuta si flooda ma non si installa
        # nulla: una regola per il flooding impedirebbe ai broadcast
        # futuri di passare dal controller.
        if out_port != ofproto.OFPP_FLOOD:
            # Match a livello 2: in_port + MAC sorgente + MAC
            # destinazione. La entry e' quindi UNIDIREZIONALE.
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

            # Ramo mai preso con n_buffers=0.
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        # [8] Nota qui non vi è controllo di host in quarantena
        # Poichè se un host è in quarantena, il pacchetto non arriva al controller

        # Con n_buffers=0 il pacchetto viaggia dentro il packet_in e va
        # rispedito indietro nel packet_out.
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        # Crea la regola di out
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _monitor(self):
        """[6] Ciclo di polling: interroga a intervalli fissi ogni switch
        registrato in self.datapaths. Girando fuori dagli handler, e' il
        solo punto in cui il controller agisce senza essere sollecitato.
        """
        while True:
            # [8] Salviamo il tempo corrente
            now = time.time()

            # [8] Per ogni chiave (MAC src) e valore (t) in flagged, se t <= now
            # ossia, la scadenza della quarantena è passata, eliminiamo la chiave dal dizionario flagged
            scaduti = [src for src, t in self.flagged.items() if t <= now]
            for src in scaduti:

                # eliminiamo la chiave dal dizionario flagged
                del self.flagged[src]

                # scriva riga di log con info che la quarantena è scaduta
                self.logger.info("quarantena scaduta %s", src)

            # [7] Stacca la finestra chiusa e la sostituisce subito: da
            # qui i packet_in scrivono sulla nuova, mentre _evaluate
            # lavora su una struttura che nessun altro tocca.
            closed = self.window
            self.window = {}
            self._evaluate(closed)

            for dp in self.datapaths.values():
                self._request_stats(dp)

            hub.sleep(5)

    def _request_stats(self, datapath):
        """[6] Invia allo switch una richiesta di statistiche e termina
        subito: la risposta arriva come evento separato, gestito da
        _flow_stats_reply_handler. Usa l'ofproto_parser del datapath.
        """
        parser = datapath.ofproto_parser

        # Costruiamo il messaggio di richiesta con cui chiediamo le flow stats
        req = parser.OFPFlowStatsRequest(datapath)

        # Invia messaggio di richiesta
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """[6] Riceve le statistiche, ne estrae i campi e li stampa.

        Questa funzione viene sollecitata ogni 5 secondi dal polling di _monitor.
        """


        # Ogni 5 secondi, quando arriva la reply, stampa il numero di entry ricevute
        # dallo switch
        self.logger.info("stats reply: %s entry", len(ev.msg.body))


        # [7] Prendi il dpid dello switch dal messaggio che ha inviato
        dpid = ev.msg.datapath.id

        # [8] In questo set, azzerato ad ogni chiamata, registriamo le entry viste in questo ciclo,
        # ossia, le chiavi (dpid, in_port, eth_src, eth_dst) delle flow entry che lo switch ha restituito.
        viste = set()

        # Le statistiche stanno in ev.msg.body, che e' una lista: una
        # voce per flow entry.
        for stat in ev.msg.body:

            # [8] ha senso fare calcoli solo sulle flow entry di inoltro ossia, il traffico unicast
            if stat.priority != 1:
                continue

            # [7] Prendiamo la Key che identifica univocamente un flow
            key = (dpid, stat.match['in_port'],
                   stat.match['eth_src'], stat.match['eth_dst'])

            # [8] Registra la entry come viva in questo ciclo.
            viste.add(key)

            # [7] Delta: calcola la differenza tra i pkt ricevuto fino a questo momento
            # ed i pkt ricevuti in questa istanza di polling. 0 è un valore che viene usato
            # se key non fa match
            prev = self.flow_prev.get(key, 0)
            delta = stat.packet_count - prev

            # [7] Aggiorna il valore di prev con il nuovo valore di pkt_count
            # ottenuto dalla flow entry 
            self.flow_prev[key] = stat.packet_count

            src = stat.match['eth_src']

            # [7] Se key non fa match usa valori default
            self.window.setdefault(src, {'arp': 0, 'dsts': set(), 'pkts': 0})

            # [7] Somma i valori del delta con i delta dagli altri flussi.
            self.window[src]['pkts'] += delta

            # Stampa con il logger dell'applicazione.
            self.logger.info("flow stats port %s %s %s %s pkt (delta %s) "
                             "%s byte %s s",
                             stat.match['in_port'],
                             stat.match['eth_src'], stat.match['eth_dst'],
                             stat.packet_count, delta, stat.byte_count,
                             stat.duration_sec)

        # [8] Elimina le entry che non sono state viste in questo ciclo di polling.

        # Per ogni chiave k in self.flow_prev, se il dpid della chiave è uguale al dpid dello switch che ha inviato la reply
        # e la chiave k non è presente nel set viste
        morte = [k for k in self.flow_prev if k[0] == dpid and k not in viste]
        for k in morte:

            # [8] Elimina la chiave k dal dizionario self.flow_prev poicheè
            # la entry è stata rimossa dallo switch e non è più presente nella reply
            del self.flow_prev[k]

    def _evaluate(self,window):
        """[7] Valuta le feature della finestra chiusa ed emette alert.

        Metodo ordinario, non handler: chiamato da _monitor.
        """
        for src, f in window.items():

            # Per ogni host in window, stampa le feature aggregate della finestra chiusa
            self.logger.info("window %s arp=%s fanout=%s pkts=%s",
                             src, f['arp'], len(f['dsts']), f['pkts'])

            # [7] Se l'host è già segnalato, salta la valutazione
            if src in self.flagged:
                continue

            # [7] Usiamo la feature 1 per segnalarlo: se supera la soglia, lo mettiamo in quarantena e scriviamo un alert.
            if f['arp'] >= self.ARP_MIN:

                # [8] Segnala l'host src come contenuto, con scadenza: time.time() + CONTAIN_SEC 
                self.flagged[src] = time.time() + self.CONTAIN_SEC

                # [7] Il fan-out qualificatore di severità
                sev = 'HIGH' if len(f['dsts']) >= self.FANOUT_MIN else 'LOW'

                self.logger.warning("ALERT %s %s arp=%s fanout=%s pkts=%s",
                                    sev, src, f['arp'], len(f['dsts']),
                                    f['pkts'])

                # [8] chiama il metodo _contain per installare la regola di drop sullo switch
                self._contain(src)

    def _contain(self, src):
        """[8] Isola l'host src installando una flow entry di drop.

        Metodo ordinario, non handler: chiamato da _evaluate.
        """
        for dp in self.datapaths.values():

            # [8] ofproto_parser definisce le classi che compongono i messaggi OpenFlow che variano
            # in base alla versione di OpenFlow negoziata con lo switch. 
            parser = dp.ofproto_parser

            # [8] Regola di match nella flow entry che aggiungeremo allo switch: matcha il MAC sorgente dell'host da contenere
            match = parser.OFPMatch(eth_src=src)

            
            self.add_flow(dp, self.DROP_PRIO, match, [],
                          hard_timeout=self.CONTAIN_SEC)

            self.logger.warning("CONTAIN %s dpid=%s prio=%s hard_timeout=%s s",
                                src, dp.id, self.DROP_PRIO, self.CONTAIN_SEC)
