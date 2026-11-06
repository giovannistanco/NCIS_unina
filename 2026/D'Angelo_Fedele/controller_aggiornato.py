#!/usr/bin/env python3

import time
from collections import defaultdict, deque
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from ryu.lib import hub

MONITOR_INTERVAL = 2 #secondi, tempo che intercorre fra due controlli del controller
WINDOW_SIZE = 10 #indica il numero massimo di dati memorizzati nella history per ciascuna porta di ciascuno switch
Z_SCORE_THRESHOLD = 2.5 #fattore moltiplicativo della deviazione standard per stabilire di quanto il traffico può superare la media prima di essere considerato anomalo
WARMUP_CYCLES = 8 #numero di cicli iniziali in cui il controller raccoglie solo campioni per costruire la baseline senza bloccare flussi
MIN_SAMPLES_FOR_STATS = 3 #numero minimo di statistiche per poter valutare la presenza di anomalie
IDLE_THRESHOLD_BPS = 100_000 #bps, soglia minima per gestire il warmup
ABSOLUTE_MIN_FLOOR_BPS = 500_000 #bps, soglia minima assoluta sotto la quale il treshold non può mai scendere per evitare falsi positivi quando c'è poco traffico
MAX_ATTACK_PACKET_SIZE = 800 #byte, dimensione media massima dei pacchetti per distinguere un flood TCP (pacchetti piccoli) da traffico dati normale
BASE_BLOCK_SECONDS = 30 #secondi, indica il tempo minimo di blocco di un flusso
MAX_BLOCK_SECONDS = 240 #secondi, indica il tempo massimo di blocco di un flusso
BLOCK_BACKOFF_FACTOR = 2 #serve per calcolare il tempo di blocco, è la base di un esponenziale
COOLDOWN_CHECK_INTERVAL = 2 #secondi, indica ogni quanto si attiva il loop di cooldown per lo sblocco dei flussi
MAX_PORT_ATTACKS = 3 #indica il massimo numero di porte TCP/UDP bloccate e associate a uno stesso IP. Quando raggiunto, il blocco avviene sull'IP sorgente

# Whitelist IP e Porte UDP legittime (es. DNS=53, NTP=123, RTP/Streaming=5004, iperf=5201)
WHITELIST_IPS = {"10.0.0.5"}
WHITELIST_UDP_PORTS = {53, 123, 5004, 5201}

#priorità utilizzate (PRIORITY_BLOCK è più alta di PRIORITY_FORWARDING così nello switch la regola di drop ha precedenza sull'inoltro normale)
PRIORITY_TABLE_MISS = 0
PRIORITY_FORWARDING = 1
PRIORITY_BLOCK = 200


class TrafficMonitor:
    """Classe responsabile del controllo del traffico"""
    def __init__(self, app):
        self.app = app #classe controller principale 
        self.datapaths = {} #dizionario di datapath {key= datapathID (dpid):value=switch}
        self.prev_stats = {} #dizionario di statistiche di un datapath {key=(datapathID,port_number):value=(previous time, previous bytes received)}

    def register(self, dp):
        """Aggiunge un datapath al dizionario interno"""
        self.datapaths[dp.id] = dp

    def unregister(self, dpid):
        """Elimina un datapath e ripulisce le relative strutture di stato"""
        self.datapaths.pop(dpid, None)
        for k in [k for k in self.prev_stats if k[0] == dpid]: #rimuovo tutte le vecchie statistiche associate alle porte dello switch disconnesso
            self.prev_stats.pop(k, None)
        self.app.cleanup_datapath_state(dpid)

    def run(self):
        """Funzione del thread monitor, il quale ogni 2 secondi richiede agli switch le statistiche sui flussi memorizzati"""
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY)) #invio richiesta per il datapath dp
            hub.sleep(MONITOR_INTERVAL) #attesa di 2 secondi
            self.app.on_monitor_tick()

    def handle_port_stats_reply(self, ev):
        """Elabora le statistiche delle porte ricevute dallo switch"""
        dpid = ev.msg.datapath.id
        now = time.time()
        for stat in ev.msg.body:
            if stat.port_no > 0xffffff00: #ignoro le porte logiche/riservate di OpenFlow (es. OFPP_LOCAL, OFPP_CONTROLLER) tenendo solo quelle fisiche
                continue

            #se la porta con port_no associata al dpid corrente non ha statistiche precedenti mi limito ad aggiungerla, altrimenti controllo prima se presenta anomalie
            key = (dpid, stat.port_no)
            if key in self.prev_stats:
                prev_time, prev_rx = self.prev_stats[key]
                dt = now - prev_time
                if dt > 0 and stat.rx_bytes >= prev_rx: 
                    bps = 8.0 * (stat.rx_bytes - prev_rx) / dt 
                    self.app.on_new_sample(dpid, stat.port_no, bps) #verifico se la porta presenta anomalie
            self.prev_stats[key] = (now, stat.rx_bytes) #inserimento nuova statistica o aggiornamento di una vecchia


class AnomalyDetector:
    """Classe responsabile dell'individuazione delle anomalie"""
    def __init__(self):
        self.history = defaultdict(lambda: deque(maxlen=WINDOW_SIZE)) #contiene bps calcolati per ogni porta {key=(dpid,port_number),value=bps}. Ve ne sono WINDOW_SIZE per ognuna
        self.warmup_active = False #diventa True non appena inizia a circolare traffico sopra la soglia di idle
        self.warmup_completed = False #diventa True quando i cicli di warmup terminano e il sistema entra a regime
        self.warmup_cycles_left = WARMUP_CYCLES #contatore dei cicli di warmup rimanenti

    def is_anomalous(self, dpid, port_no, current_bps):
        """Verifica se il traffico che attraversa una porta è anomalo."""
        key = (dpid, port_no)
        if current_bps < IDLE_THRESHOLD_BPS: #se una porta trasmette a meno di IDLE_THRESHOLD_BPS, allora restituisco (False,Treshold minimo)
            return False, ABSOLUTE_MIN_FLOOR_BPS 

        if not self.warmup_completed: #se il warmup non è completo, si limita a salvare il current_bps della porta (dpid,port_number) per il calcolo della baseline
            self.warmup_active = True
            self.history[key].append(current_bps)
            return False, None

        samples = list(self.history[key]) #prelievo di tutti i valori di bps associati alla porta
        if len(samples) >= MIN_SAMPLES_FOR_STATS: #entro qui se ho abbastanza campioni 
            mean = sum(samples) / len(samples) #calcolo della media dei campioni storici della porta
            std_dev = (sum((x - mean) ** 2 for x in samples) / len(samples)) ** 0.5 #calcolo della deviazione standard per valutare la variabilità del traffico
            threshold = max(mean + Z_SCORE_THRESHOLD * std_dev, ABSOLUTE_MIN_FLOOR_BPS) #calcolo del nuovo treshold
        elif samples: #entro qui se ho meno di MIN_SAMPLES_FOR_STATS campioni
            threshold = max((sum(samples) / len(samples)) * 1.5, ABSOLUTE_MIN_FLOOR_BPS)
        else: #entro qui se non ho campioni
            threshold = ABSOLUTE_MIN_FLOOR_BPS

        return current_bps > threshold, threshold


class MitigationEnforcer:
    """Classe responsabile della creazione delle regole di blocco e sblocco di un flusso"""
    def __init__(self, app):
        self.app = app
        self.blocklist = defaultdict(dict) #dizionario di flussi bloccati {key=dpid:value=dizionario rappresentante un flusso}
        self.seen_ports = defaultdict(set) #dizionario di porte TCP/UDP bloccate e associate a uno stesso IP {key= (id switch, IP/MAC host) : value=porta TCP/UDP}

    def match_key(self, fields):
        """Restituisce una tupla ordinata contenente le coppie chiave-valore di fields"""
        return tuple(sorted(fields.items())) #converto il dict fields in tupla ordinata per poterla usare come chiave nei dizionari (blocklist e prev_flow_stats)

    def is_host_globally_blocked(self, dpid, host_id,now=None):
        """Restituisce True se il flusso indirizzato da (dpid,host_id) è globalmente bloccato (ossia se ha attaccato da più di MAX_PORT_ATTACKS porte)"""
        if now is None:
            now = time.time()
        return any(
            e['active'] and e['host_id'] == host_id and e['is_global'] and e['expire'] > now
            for e in self.blocklist[dpid].values()
        )

    def is_blocked(self, dpid, entry=None, fields=None,now=None):
        """Restituisce True se il flusso entry, o quello ricavato dal campo fields, è bloccato"""
        if now is None:
            now = time.time()
        if entry is not None:
            fields = entry.get('match_fields')
        elif fields is not None:
            entry = self.blocklist[dpid].get(self.match_key(fields))
        else:
            return

        if entry and entry['active'] and entry['expire'] > now: #se il flusso è presente in blocklist e se presenta un blocco attivo ma non ancora scaduto restituisco true
            return True
        
        #se invece risulta non bloccato, devo controllare che non lo sia nemmeno a livello globale
        src_ip = fields.get('ipv4_src')
        return bool(src_ip and self.is_host_globally_blocked(dpid, src_ip, now))
    
    def block_flow(self, dp, fields):
        """Blocca il flusso sullo switch dp e indirizzato da fields"""
        if fields.get('eth_type') == ether_types.ETH_TYPE_ARP: #non blocco mai i pacchetti ARP altrimenti gli host non potrebbero più risolvere gli indirizzi IP in MAC
            return

        dpid = dp.id
        src_ip = fields.get('ipv4_src')
        host_id = src_ip if src_ip else fields.get('eth_src') 
        now = time.time()

        #se host_id non esiste o ha blocco globale non faccio nulla.
        if not host_id or self.is_host_globally_blocked(dpid, host_id, now):
            return

        if self.is_blocked(dpid, fields=fields, now=now): #se il flusso indicato da fields esiste ed è già bloccato non faccio nulla
            return

        key = self.match_key(fields) #costruzione della chiave
        entry = self.blocklist[dpid].get(key) #entry contiene tutti i dati relativi al flusso bloccato

        # Tracciamento porte TCP/UDP per rilevare attacchi che cambiano porta sorgente
        l4_port = fields.get('udp_src') or fields.get('tcp_src')
        if l4_port is not None:
            self.seen_ports[(dpid, host_id)].add(l4_port)

        ports_cnt = len(self.seen_ports[(dpid, host_id)]) 
        is_changing_ports = ports_cnt >= MAX_PORT_ATTACKS #true se ho bloccato più di MAX_PORT_ATTACKS flussi con porte source diverse ma stesso IP source 
        prev_strikes = entry['strikes'] if entry else 0 #prelievo del numero di attacchi precedenti provenienti dallo stesso flusso

        if src_ip and is_changing_ports: #entro qui se l'attaccante sta cambiando porte 
            in_port = fields.get('in_port')
            fields = {'eth_type': ether_types.ETH_TYPE_IP, 'ipv4_src': src_ip} #ricostruisco fields, in modo da bloccare l'IP source
            if in_port is not None:
                fields['in_port'] = in_port

            if self.is_blocked(dpid,fields=fields,now=now): #se già bloccato non faccio nulla
                return

            #ricostruzione di key ed entry a partire dal nuovo fields
            key = self.match_key(fields)
            entry = self.blocklist[dpid].get(key)
            if entry:
                prev_strikes = max(prev_strikes, entry['strikes']) #quando passo al blocco globale sull'IP conservo il numero massimo di recidive accumulato fino a quel momento

        strikes = prev_strikes + 1
        b_sec = min(BASE_BLOCK_SECONDS * (BLOCK_BACKOFF_FACTOR ** (strikes - 1)), MAX_BLOCK_SECONDS) #scelgo per quanti secondi la regola di drop deve rimanere valida

        #inserimento/update dati del nuovo blocco
        self.blocklist[dpid][key] = {
            'expire': now + b_sec,
            'strikes': strikes,
            'match_fields': fields,
            'host_id': host_id,
            'is_global': bool(src_ip and is_changing_ports),
            'active': True
        }

        self.remove_forwarding_rule(dp, fields, strict=not (src_ip and is_changing_ports)) #comanda agli switch di rimuovere tutte le regole di forwarding apprese per il flusso indirizzato da fields
        self.install_drop_rule(dp, fields) #installa la regola di drop per il flusso indirizzato da fields
        self.app.clear_flow_stats_for_match(dpid, fields) #rimuove solo le statistiche dei flussi relative allo switch/flusso bloccato

        self.app.logger.warning(
            "[MITIGATION: %s] Blocco flow %s su switch %s per %ds (recidiva #%d, porte_distinte=%d)",
            self.app.createTimeString(now), fields, dpid, b_sec, strikes, ports_cnt
        )

    def cooldown_loop(self):
        """Routine eseguita dal thread responsabile dello sblocco dei flussi"""
        while True:
            now = time.time()
            for dpid, flows in list(self.blocklist.items()):
                for entry in list(flows.values()):
                    if entry['active'] and now >= entry['expire']:
                        entry['active'] = False #disattiva il blocco 
                        dp = self.app.monitor.datapaths.get(dpid)
                        if dp:
                            self.remove_drop_rule(dp, entry['match_fields']) # rimuove la regola di drop
                            self.app.logger.info(
                                "[MITIGATION: %s] Sblocco flow %s su switch %s",
                                self.app.createTimeString(now), entry['match_fields'], dpid
                            )
            hub.sleep(COOLDOWN_CHECK_INTERVAL)

    def remove_forwarding_rule(self, dp, fields, strict=True):
        """Rimuove una regola di forwarding"""
        ofp, parser = dp.ofproto, dp.ofproto_parser
        cmd = ofp.OFPFC_DELETE_STRICT if strict else ofp.OFPFC_DELETE # per eliminare la regola della singola porta, oppure per rimuovere tutte le regole di inoltro di quell'host
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, command=cmd, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
            priority=PRIORITY_FORWARDING, match=parser.OFPMatch(**fields)
        ))

    def install_drop_rule(self, dp, fields):
        """Aggiunge una regola di drop"""
        p = dp.ofproto_parser
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, priority=PRIORITY_BLOCK, match=p.OFPMatch(**fields), instructions=[] 
        ))

    def remove_drop_rule(self, dp, fields):
        """Rimuove una regola di drop"""
        ofp, p = dp.ofproto, dp.ofproto_parser
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, command=ofp.OFPFC_DELETE_STRICT, out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY, priority=PRIORITY_BLOCK, match=p.OFPMatch(**fields)
        ))


class DoSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DoSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {} #crea associazione porta-MAC {key=switch ID, value={key=MAC,value=porta switch}}
        self.monitor = TrafficMonitor(self)
        self.detector = AnomalyDetector()
        self.enforcer = MitigationEnforcer(self)
        self.pending_flow_lookup = {} # Dizionario{key=(dpid, xid):value=(port_no, excess, current_bps, threshold)} contiene le statistiche per ogni porta
        self.pending_ports = set() # Set di (dpid, port_no) con richiesta già in corso
        self.multipart_flow_buffer = defaultdict(list) # Buffer per gestire risposte FlowStats multipart {key=(dpid, xid):value=[stat, ...]}
        self.prev_flow_stats = {} # Dizionario {key=(dpid,match_key):value=(time, byte_count, duration)}
        self.monitor_thread = hub.spawn(self.monitor.run) #avvio il thread che richiede periodicamente le statistiche delle porte agli switch
        self.cooldown_thread = hub.spawn(self.enforcer.cooldown_loop) #avvio il thread che controlla la scadenza dei blocchi e rimuove le regole di drop

    def cleanup_datapath_state(self, dpid):
        """Pulisce i dati associati a uno switch che si è disconnesso"""
        self.mac_to_port.pop(dpid, None)
        self.enforcer.blocklist.pop(dpid, None)
        for k in [k for k in self.pending_flow_lookup if k[0] == dpid]: #elimino eventuali richieste FlowStats in sospeso per lo switch disconnesso
            port_no = self.pending_flow_lookup.pop(k)[0]
            self.pending_ports.discard((dpid, port_no))
            self.multipart_flow_buffer.pop(k, None)
        for k in [k for k in self.prev_flow_stats if k[0] == dpid]: #elimino lo storico dei byte dei flussi dello switch disconnesso
            self.prev_flow_stats.pop(k, None)

    def clear_flow_stats_for_match(self, dpid, blocked_fields):
        """Rimuove da prev_flow_stats solo i flussi dello switch che matchano i campi bloccati"""
        to_delete = []
        for (f_dpid, f_key_tuple) in self.prev_flow_stats:
            if f_dpid != dpid:
                continue
            flow_dict = dict(f_key_tuple)
            if all(flow_dict.get(k) == v for k, v in blocked_fields.items()): #se il flusso corrisponde ai campi bloccati lo rimuovo da prev_flow_stats per non riusare i vecchi contatori dopo lo sblocco
                to_delete.append((f_dpid, f_key_tuple))
        for k in to_delete:
            self.prev_flow_stats.pop(k, None)

    def on_monitor_tick(self):
        if self.detector.warmup_active and not self.detector.warmup_completed: #ad ogni ciclo del monitor decremento i cicli di warmup rimanenti fino a entrare a regime
            self.detector.warmup_cycles_left -= 1
            self.logger.info(
                "[WARMUP] Calibrazione baseline in corso... (%d cicli rimanenti)",
                self.detector.warmup_cycles_left
            )
            if self.detector.warmup_cycles_left <= 0:
                self.detector.warmup_completed, self.detector.warmup_active = True, False
                self.logger.info("[WARMUP] Fase di warm-up completata! Sistema a regime (Enforcement attivo).")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Installa la regola di default nei nuovi switch"""
        dp = ev.msg.datapath
        ofp, p = dp.ofproto, dp.ofproto_parser
        self.add_flow(
            dp, PRIORITY_TABLE_MISS, p.OFPMatch(),
            [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)], 0, 0 #installo la regola di table-miss (priorità 0, match vuoto) per inviare al controller i pacchetti senza regola nello switch
        )

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        """Registra un nuovo datapath"""
        if ev.state == MAIN_DISPATCHER: #lo switch ha completato la negoziazione ed è operativo, quindi lo registro nel monitor
            self.monitor.register(ev.datapath)
        elif ev.state == DEAD_DISPATCHER: #lo switch si è disconnesso, quindi lo rimuovo dal monitor e pulisco il suo stato
            self.monitor.unregister(ev.datapath.id)

    def add_flow(self, dp, prio, match, actions, idle_to=10, hard_to=30, buf_id=None):
        """Aggiunge una regola di forwarding nello switch"""
        ofp, p = dp.ofproto, dp.ofproto_parser
        inst = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        b = buf_id if buf_id is not None else ofp.OFP_NO_BUFFER
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, buffer_id=b, priority=prio, match=match,
            instructions=inst, idle_timeout=idle_to, hard_timeout=hard_to #imposto idle_timeout e hard_timeout per far scadere le regole inattive o vecchie ed evitare di riempire la tabella dello switch
        ))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Gestisce l'arrivo di un pacchetto appartenente a un flow non noto"""
        msg = ev.msg
        dp, ofp, p = msg.datapath, msg.datapath.ofproto, msg.datapath.ofproto_parser
        in_port, pkt = msg.match['in_port'], packet.Packet(msg.data)
        
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP: #ignora i pacchetti di esplorazione della topologia (LLDP)
            return

        self.mac_to_port.setdefault(dp.id, {})[eth.src] = in_port #crea associazione fra porta d'ingresso e MAC mittente
        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD) #cerca la porta di uscita a partire dal MAC di destinazione. Se esiste out_port assume il valore di quella porta, altrimenti assume il valore OFPP_FLOOD 
        actions = [p.OFPActionOutput(out_port)] #costruzione dell'azione: 'invia a porta out_port'
        
        fields = self.build_match_fields(pkt, in_port) #costruzione del fields
        if fields and self.enforcer.is_blocked(dp.id, fields=fields): #se il flusso indirizzato da fields è bloccato non faccio nulla
            return

        #costruzione della regola da installare nello switch, qualora la porta out_port non sia OFPP_FLOOD
        if out_port != ofp.OFPP_FLOOD and fields:
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                self.add_flow(dp, PRIORITY_FORWARDING, p.OFPMatch(**fields), actions, buf_id=msg.buffer_id)
                return
            self.add_flow(dp, PRIORITY_FORWARDING, p.OFPMatch(**fields), actions)

        #invio del pacchetto al prossimo switch
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(p.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data
        ))

    def build_match_fields(self, pkt, in_port):
        """Costruisce i match fields a partire dai dati del pacchetto e dalla sua porta di ingresso
           Possibili fields sono:
           - {'in_port','eth_type','eth_src','eth_dst'} in caso di pacchetti che non siano IP
           - {'in_port','eth_type','ipv4_src','ipv4_dst','ip_proto'} in caso di pacchetti IP
           - {'in_port','eth_type','ipv4_src','ipv4_dst','ip_proto','tcp_src',tcp_dst} in caso di pacchetti TCP
           - {'in_port','eth_type','ipv4_src','ipv4_dst','ip_proto','udp_src',udp_dst} in caso di pacchetti UDP
        """
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        #entro qui se il pacchetto non è IP, in tal caso fields ={'in_port','eth_type','eth_src','eth_dst'}
        if not ip_pkt:
            return {'in_port': in_port, 'eth_type': eth.ethertype, 'eth_src': eth.src, 'eth_dst': eth.dst}

        f = {
            'in_port': in_port,
            'eth_type': ether_types.ETH_TYPE_IP,
            'ipv4_src': ip_pkt.src,
            'ipv4_dst': ip_pkt.dst,
            'ip_proto': ip_pkt.proto
        }
        t, u = pkt.get_protocol(tcp.tcp), pkt.get_protocol(udp.udp) #se il pacchetto IP contiene TCP o UDP aggiungo al match anche le porte sorgente e destinazione di livello 4
        if t:
            f['tcp_src'], f['tcp_dst'] = t.src_port, t.dst_port
        elif u:
            f['udp_src'], f['udp_dst'] = u.src_port, u.dst_port
        return f

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        self.monitor.handle_port_stats_reply(ev)

    def on_new_sample(self, dpid, port_no, current_bps):
        """Controlla se il flusso di dati su una porta di uno switch è anomalo. Se sì richiede statistiche sui flussi dello switch, altrimenti aggiorna lo storico della porta"""
        anomalous, threshold = self.detector.is_anomalous(dpid, port_no, current_bps) #controllo se il flusso di dati sulla porta è anomalo
        if anomalous:
            excess = current_bps - threshold #vedo di quanto è stato sforato il treshold
            dp = self.monitor.datapaths.get(dpid)
            # invio di una richiesta di statistiche dei flussi, qualora non ce ne sia già una in corso
            if dp and (dpid, port_no) not in self.pending_ports:
                req = dp.ofproto_parser.OFPFlowStatsRequest(
                    dp, match=dp.ofproto_parser.OFPMatch(in_port=port_no)
                )
                dp.set_xid(req) #assegno un id univoco (xid) alla richiesta per associare la risposta asincrona dello switch alla porta in anomalia
                self.pending_ports.add((dpid, port_no)) #aggiungo la porta al dizionario di pending ports
                self.pending_flow_lookup[(dpid, req.xid)] = (port_no, excess, current_bps, threshold) #aggiungo la richiesta al dizionario di pending requests
                dp.send_msg(req) #invio richiesta
        elif threshold is not None and self.detector.warmup_completed and current_bps >= IDLE_THRESHOLD_BPS: 
            self.detector.history[(dpid, port_no)].append(current_bps) #se non ci sono anomalie posso aggiungere current_bps allo storico della porta

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Gestisce l'arrivo delle statistiche del flusso di una porta di uno switch"""
        dp, dpid = ev.msg.datapath, ev.msg.datapath.id
        lookup_key = (dpid, ev.msg.xid)
        if lookup_key not in self.pending_flow_lookup: #se la richiesta per questa chiave è già stata ricevuta non fa nulla
            return

        # Accumula i flussi nel buffer (gestione messaggi multipart OFPMPF_REPLY_MORE). Se ce ne sono altri in arrivo non fa nulla
        self.multipart_flow_buffer[lookup_key].extend(ev.msg.body)
        if ev.msg.flags & dp.ofproto.OFPMPF_REPLY_MORE:
            return

        #prelievo delle statistiche del flusso 
        port_no, excess_bps, current_bps, threshold = self.pending_flow_lookup.pop(lookup_key) 
        self.pending_ports.discard((dpid, port_no))
        stats_body = self.multipart_flow_buffer.pop(lookup_key, [])

        #verifico se la porta ha qualche blocco
        now = time.time()
        has_block = False
        for e in self.enforcer.blocklist[dpid].values():
            has_block = has_block or (self.enforcer.is_blocked(dpid,entry=e,now=now) and e['match_fields'].get('in_port') == port_no)

        #Prelievo dei flussi che attraversano la porta
        candidates = []
        for stat in stats_body:
            # Ignora le regole che non sono di forwarding o senza traffico
            if stat.priority != PRIORITY_FORWARDING or stat.byte_count == 0:
                continue

            dur = max(stat.duration_sec + (stat.duration_nsec / 1e9), 0.001) # metto un tempo minimo perché se ho un picco di traffico in un tempo piccolo ottengo rate molto alti, ma non dannosi (perché brevi)
            fkey = (dpid, self.enforcer.match_key(dict(stat.match.items())))
            
            #se fkey è stato già analizzato utilizzo anche le vecchie statistiche per calcolare il rate nuovo, altrimenti utilizzo solo quelle che ho a disposizione
            if fkey in self.prev_flow_stats: 
                prevTime, prevByte, prevDur = self.prev_flow_stats[fkey]
                dt = now - prevTime
                if dt > 0 and dur >= prevDur and stat.byte_count >= prevByte: #entro qui se i dati trovati sono consistenti
                    rate = 8.0 * (stat.byte_count - prevByte) / dt
                else:
                    rate = (8.0 * stat.byte_count) / dur
            else:
                rate = (8.0 * stat.byte_count) / dur

            self.prev_flow_stats[fkey] = (now, stat.byte_count, dur)
            candidates.append((rate, stat.byte_count / max(stat.packet_count, 1), stat.match)) #salvo per ogni flusso il rate in bps, la dimensione media dei pacchetti (byte_count/packet_count) e i campi di match

        if not candidates: #se non ci sono flussi sulla porta posso terminare
            return

        candidates.sort(key=lambda c: c[0], reverse=True) #riordino candidates sul rate
        attack_blocked = False
        whitelisted_anomaly = False

        # Scorriamo i candidati: se il primo è in whitelist, non lo blocchiamo ma controlliamo
        # comunque se ci sono altri flussi anomali sulla stessa porta.
        for rate_bps, avg_pkt_size, match in candidates:
            fields = dict(match.items())
            ip_proto = fields.get('ip_proto')

            # Se il candidato non supera il 60% dell'eccesso (o ha pacchetti grandi non-UDP), non è un attacco
            if not (rate_bps >= 0.60 * excess_bps and (ip_proto == 17 or avg_pkt_size <= MAX_ATTACK_PACKET_SIZE)): #ip_proto == 17 indica UDP (dove i flood possono avere anche pacchetti grandi), mentre su TCP considero attacco solo flussi con pacchetti piccoli (es. SYN flood)
                continue

            #Controllo Whitelist IP sorgente
            if fields.get('ipv4_src') in WHITELIST_IPS:
                self.logger.info(
                    "[MITIGATION: %s] IP %s è in whitelist, non blocco. Aggiorno baseline.",
                    self.createTimeString(now), fields.get('ipv4_src')
                )
                whitelisted_anomaly = True
                continue

            #Controllo Whitelist Porte UDP legittime (sia sorgente che destinazione)
            udp_src = fields.get('udp_src')
            udp_dst = fields.get('udp_dst')
            if ip_proto == 17 and (udp_src in WHITELIST_UDP_PORTS or udp_dst in WHITELIST_UDP_PORTS):
                self.logger.info(
                    "[MITIGATION: %s] Flusso UDP su porta legittima (src=%s, dst=%s) in whitelist, non blocco. Aggiorno baseline.",
                    self.createTimeString(now), udp_src, udp_dst
                )
                whitelisted_anomaly = True
                continue

            # Se non è in whitelist, procediamo al blocco del flusso
            self.enforcer.block_flow(dp, fields)
            attack_blocked = True
            break

        # Se non è stato bloccato alcun attacco e non ci sono blocchi attivi sulla porta, aggiorniamo la baseline per ricalcolare la soglia adattiva.
        if not attack_blocked and not has_block:
            top_rate, _, top_match = candidates[0]
            top_proto = dict(top_match.items()).get('ip_proto')
            if whitelisted_anomaly or (top_rate > 0 and top_proto is not None): #se il picco era dovuto a traffico in whitelist o comunque lecito aggiungo il valore alla history così la soglia si adatta senza generare falsi allarmi nei cicli successivi
                self.detector.history[(dpid, port_no)].append(current_bps)
    
    def createTimeString(self,time_sec):
        t_local = time.localtime(time_sec) #converte il timestamp in ora locale per formattare l'orario nei log (HH:MM:SS)
        return str(t_local.tm_hour) + ":" + str(t_local.tm_min) + ":" + str(t_local.tm_sec)