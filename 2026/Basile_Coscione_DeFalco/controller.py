from ryu.base import app_manager        # Ryu gestisce tutte le applicazioni SDN con la classe base
from ryu.controller import ofp_event    # Modulo eventi OpenFlow
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER   # Gestori di stato della sessione OpenFlow
from ryu.controller.handler import set_ev_cls # decoratore: collega una funzione a un evento OpenFlow                          
from ryu.ofproto import ofproto_v1_3     # Costanti di OpenFlow v1.3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp          # Ci serve per l'ARP proxy
from ryu.lib import hub                 # Libreria di threading per far girare il modulo di monitoraggio in un thread suo in background
import time                             # Ci serve per sapere l'istante di ogni lettura
import json                             # Ci serve per leggere il file policy.json


# TABELLA DELLA RETE 

ACCESS_SWITCHES = [1, 2, 3] # dpid degli switch di accesso (s1, s2, s3)
UPPER_SWITCH = 4            # dpid di s4, switch di transito della slice UPPER
LOWER_SWITCH = 5            # dpid di s5, switch di transito della slice LOWER
PORT_UPPER = 1              # porta di ogni switch di accesso verso s4
PORT_LOWER = 2              # porta di ogni switch di accesso verso s5 (percorso secondario)
TRANSIT_PORT = {1: 1,
                2: 2,
                3: 3}   # dizionario: (chiave) switch di accesso -> (valore) porta di s4/s5 verso di lui

# host: (IP, MAC, switch di accesso a cui è attaccato, porta di quello switch)
HOSTS = [
    ('10.0.0.1', '00:00:00:00:00:01', 1, 3),   # h1 sorgente UDP
    ('10.0.0.2', '00:00:00:00:00:02', 1, 4),   # h2 sorgente TCP
    ('10.0.0.3', '00:00:00:00:00:03', 2, 3),   # h3 sorgente UDP
    ('10.0.0.4', '00:00:00:00:00:04', 2, 4),   # h4 sorgente TCP
    ('10.0.0.5', '00:00:00:00:00:05', 3, 3),   # h5 server
]

PRIO_MISS = 0               # table-miss
PRIO_DROP_V6 = 1            # IPv6 scartato sullo switch 
PRIO_FORWARD = 10           # inoltro normale
PRIO_BLOCK = 30             # blocco deciso dall'amministratore
PRIO_ARP = 100              # ARP al controller

UPPER_CAPACITY = 10000000   # capacità dei link verso s4 in bit/s (= UPPER_BW di topology.py)


DEFENSE_ENABLED = True      # True: controller completo (Monitoraggio + Detection + Enforcement + Policy)
                            # False: solo inoltro, ARP proxy e Monitoraggio


# PARAMETRI MONITORAGGIO
MONITOR_INTERVAL = 1        # Intervallo in secondi tra una lettura dei contatori e la successiva
SHOW_MIN_RATE = 100000      # nel log mostriamo solo ciò che supera 0,1 Mbit/s (i ping no)

# PARAMETRI DETECTION
DETECT_INTERVAL = 1         # Intervallo in secondi tra un controllo e il successivo
CONGESTION_LEVEL = 0.8      # Livello di congestione: si avvera quando il link supera l'80% di capacità
FAIR_FACTOR = 2             # Fattore per rilevare chi prende più del doppio della sua parte equa
DETECT_SECONDS = 3          # Numero di secondi necessari per confermare un sospetto e spostare in LOWER
RELEASE_SECONDS = 5         # Numero di secondi necessari in cui la banda non deve superare la parte equa per riammettere in UPPER 
ACTIVE_MIN = 100000         # Minimo flusso (sopra 0,1 Mbit/s) per essere visto attivo
ACTIVE_WINDOW = 10          # N conta i flussi attivi su UPPER negli ultimi 10 secondi

# PARAMETRI  POLICY 
POLICY_FILE = 'policy.json' # Il file dell'amministratore
POLICY_INTERVAL = 1         # ogni quanti secondi il file viene riletto


# Dato un MAC, restituisce l'IP dell'host.
def host_ip(mac):
    for ip, host_mac, access, port in HOSTS:
        if host_mac == mac:
            return ip
    return mac


# Dato un MAC, restituisce lo switch di accesso a cui è attaccato l'host
def host_switch(mac):
    for ip, host_mac, access, port in HOSTS:
        if host_mac == mac:
            return access
    return None


# Dato un IP, restituisce il MAC dell'host.
def host_mac(ip):
    for host_ip_address, mac, access, port in HOSTS:
        if host_ip_address == ip:
            return mac
    return None


class DynamicSlicing(app_manager.RyuApp):           
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]   # versione OpenFlow supportata

    def __init__(self, *args, **kwargs):        # costruttore
        super(DynamicSlicing, self).__init__(*args, **kwargs) #cerca genitore della classe DynamicSlicing a cui appartiene oggetto self ed esegui il suo costruttore init scaricandogli addosso args e kwargs
        
        self.datapaths = {}                     # dizionario dei canali OpenFlow attivi: dpid -> switch

        # Dati del Monitoraggio
        # N.B: un flusso lo riconosciamo dalla coppia (mac_src, mac_dst)
        self.flow_last = {}     # (mac_src, mac_dst) -> (byte contati, ultima lettura del suo contatore)
        self.flow_rate = {}     # (mac_src, mac_dst) -> (quanti bit/s sta mandando ora, misurati sullo switch di accesso d'ingresso)
        self.link_last = {}     # switch di accesso -> (ultima lettura dei byte inviati da s4 verso di lui)
        self.link_rate = {}     # switch di accesso -> (bit/s sul link s4 -> switch, quanto è carico il link da s4 verso di lui)

        # Dati della Detection
        self.upper_seen = {}    # flusso -> ultimo istante in cui era attivo su UPPER (via s4)
        self.on_lower = []      # lista dei flussi (mac_src, mac_dst) spostati su LOWER
        self.over_count = {}    # flusso -> secondi di fila sopra la soglia
        self.under_count = {}   # flusso su LOWER -> secondi di fila sotto la parte equa

        # Qui Detection e Policy lasciano gli ordini (sposta, riammetti, blocca, sblocca) e l'Enforcement li esegue uno alla volta
        self.orders = hub.Queue()

        # Le regole dell'amministratore, come la Policy le ha lette da policy.json
        # Ogni lista contiene flussi (mac_src, mac_dst), gia' tradotti dagli IP
        self.policy = {'block': [], 'allow': [], 'lower': []}
        self.policy_raw = None      # il file com'era all'ultima lettura: se non è cambiato, non si rifà niente
        self.policy_error = ''      # l'ultimo errore di lettura: finisce nel log una volta sola

        # Ogni modulo gira in un thread tutto suo, separato dagli altri
        self.monitoring_thread = hub.spawn(self.monitoring)
        if DEFENSE_ENABLED:
            self.detection_thread = hub.spawn(self.detection)
            self.enforcement_thread = hub.spawn(self.enforcement)
            self.policy_thread = hub.spawn(self.policy_reader)
        else:
            self.logger.info('[CFG] DEFENSE_ENABLED = False: il controller misura soltanto, nessuna difesa attiva')

    # MODULO 1: FORWARDING E ARP PROXY
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        # Dall'evento scatenato da Ryu ricaviamo:

        datapath = ev.msg.datapath              # lo switch che si e' collegato
        ofproto = datapath.ofproto              # costanti di OpenFlow 1.3
        parser = datapath.ofproto_parser        # costruttori dei messaggi OpenFlow
        self.datapaths[datapath.id] = datapath  # viene salvato all'interno di un dizionario accessibile con chiave id

        # Table-miss: match vuoto (prende tutti i pacchetti), priorita' 0, manda al controller.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, PRIO_MISS, match, actions)

        # Pacchetti di tipo IPv6: li scarto subito sullo switch, con action vuota. Vale per tutti gli switch. Priorità 1 appena sopra Table-Miss.
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
        self.add_flow(datapath, PRIO_DROP_V6, match, [])

        if datapath.id == UPPER_SWITCH or datapath.id == LOWER_SWITCH:
            # Riguarda switch di transito s4, s5: per ogni host, se la destinazione è lui scendi verso il suo switch
            for ip, mac, access, port in HOSTS:
                match = parser.OFPMatch(eth_dst=mac)
                actions = [parser.OFPActionOutput(TRANSIT_PORT[access])]
                self.add_flow(datapath, PRIO_FORWARD, match, actions)
            self.logger.info('[FWD] s%d pronto (transito)', datapath.id)

        elif datapath.id in ACCESS_SWITCHES:
            # Riguarda switch di accesso s1, s2 e s3: i pacchetti ARP vanno al controller
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, PRIO_ARP, match, actions)

            # Un host attaccato ad s1, s2 o s3 (switch di accesso) esce dalla sua rispettiva porta (consegna locale)
            for ip, mac, access, port in HOSTS:
                if access == datapath.id:
                    match = parser.OFPMatch(eth_dst=mac)
                    actions = [parser.OFPActionOutput(port)]
                    self.add_flow(datapath, PRIO_FORWARD, match, actions)

            # Riguarda switch di accesso s1, s2 e s3: per ogni coppia (host src -> host dst): intraprende il percorso su s4 (UPPER)
            for src_ip, src_mac, src_access, src_port in HOSTS:
                for dst_ip, dst_mac, dst_access, dst_port in HOSTS:
                    if src_access == datapath.id and dst_access != datapath.id:
                        match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
                        actions = [parser.OFPActionOutput(PORT_UPPER)]
                        self.add_flow(datapath, PRIO_FORWARD, match, actions)
            self.logger.info('[FWD] s%d pronto (accesso)', datapath.id)

    # Aggiunge una regola (flow entry) allo switch
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] # Istruzione: "applica queste azioni ai pacchetti che corrispondono al match".
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)                  # il messaggio parte verso lo switch

    # Chiamata ogni volta che uno switch ci passa un pacchetto (packet-in). Da noi arrivano: le regole ARP e le table-miss.
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg                            # il messaggio
        datapath = msg.datapath                 # lo switch che lo ha mandato
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']          # porta da cui è entrato il pacchetto

        pkt = packet.Packet(msg.data)                   # i byte arrivati dallo switch trasformati in un pacchetto leggibile
        eth = pkt.get_protocols(ethernet.ethernet)[0]   # il suo header Ethernet: MAC src, MAC dst, tipo

        if eth.ethertype != ether_types.ETH_TYPE_ARP:   # non è ARP ma è arrivato dalla table-miss, quindi manca una regola
            self.logger.info('[MISS] s%d porta %d: da %s a %s senza regola, scartato',
                             datapath.id, in_port, eth.src, eth.dst)
            return                                      # lo segnaliamo e basta, senza packet-out il pacchetto è perso

        req = pkt.get_protocols(arp.arp)[0]             # è ARP: leggo chi chiede e quale IP cerca
        if req.opcode != arp.ARP_REQUEST:               # rispondiamo solo alle domande, non alle risposte
            return

        target_mac = host_mac(req.dst_ip)               # il MAC dell'IP cercato, dalla tabella HOSTS
        if target_mac is None:                          # IP che non fa parte della rete: nessuna risposta
            return        

        # Costruzione della risposta
        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(dst=req.src_mac, src=target_mac,
                                             ethertype=ether_types.ETH_TYPE_ARP))
        reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                   src_mac=target_mac, src_ip=req.dst_ip,
                                   dst_mac=req.src_mac, dst_ip=req.src_ip))
        reply.serialize()                       # la trasformo in byte

        # Packet-out: la risposta esce SOLO dalla porta dell'host che ha chiesto.
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions, data=reply.data)
        datapath.send_msg(out)
        self.logger.info('[ARP] s%d: detto a %s che %s e\' %s',
                         datapath.id, req.src_ip, req.dst_ip, target_mac)

    # MODULO 2: MONITORAGGIO: ogni secondo chiede i contatori e stampa i rate.
    def monitoring(self):
        while True:
            # list(...) fa una copia del dizionario
            for datapath in list(self.datapaths.values()):
                parser = datapath.ofproto_parser
                if datapath.id in ACCESS_SWITCHES:
                    # chiede agli switch di accesso i contatori di tutte le regole
                    req = parser.OFPFlowStatsRequest(datapath)
                    datapath.send_msg(req)
                if datapath.id == UPPER_SWITCH:
                    # chiede a s4 i contatori di tutte le sue porte
                    req = parser.OFPPortStatsRequest(datapath)
                    datapath.send_msg(req)
            hub.sleep(MONITOR_INTERVAL)         # pausa di 1 s che lascia lavorare il resto del controller
            self.show_rates()

    # Risposta di uno switch di accesso: i contatori delle sue regole.
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        now = time.time()                       # istante di questa lettura, in secondi
        for stat in ev.msg.body:                # una 'stat' per ogni regola dello switch
            # Ci interessano solo le regole di coppia: priorità 10 e con un mittente (le consegne locali hanno priorità 10 ma solo il destinatario.)
            if stat.priority != PRIO_FORWARD or 'eth_src' not in stat.match:
                continue                        # salta questa regola, passa alla prossima
            pair = (stat.match['eth_src'], stat.match['eth_dst'])
            if pair in self.flow_last:
                old_bytes, old_time = self.flow_last[pair]
                # rate = (byte nuovi - byte vecchi) * 8 / tempo trascorso  -> bit al secondo
                self.flow_rate[pair] = (stat.byte_count - old_bytes) * 8 / (now - old_time)
            self.flow_last[pair] = (stat.byte_count, now)   # la lettura di adesso diventa la "vecchia"

    # Risposta di s4: i contatori delle sue porte (ogni porta va a uno switch di accesso).
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        now = time.time()
        for stat in ev.msg.body:                # una 'stat' per ogni porta di s4
            for access in TRANSIT_PORT:
                if TRANSIT_PORT[access] == stat.port_no:  # questa porta va verso questo switch
                    if access in self.link_last:
                        old_bytes, old_time = self.link_last[access]
                        # tx_bytes = byte usciti dalla porta, cioe' scesi da s4 verso lo switch di accesso
                        self.link_rate[access] = (stat.tx_bytes - old_bytes) * 8 / (now - old_time)
                    self.link_last[access] = (stat.tx_bytes, now)

    # Stampa i link e i flussi che superano SHOW_MIN_RATE.
    def show_rates(self):
        for access in ACCESS_SWITCHES:
            if access in self.link_rate and self.link_rate[access] > SHOW_MIN_RATE:
                rate = self.link_rate[access]
                self.logger.info('[MON] link s4 -> s%d: %.1f Mbit/s (%d%% della capacita\')',
                                 access, rate / 1000000, 100 * rate / UPPER_CAPACITY)
        for src, dst in self.flow_rate:
            rate = self.flow_rate[(src, dst)]
            if rate > SHOW_MIN_RATE:
                self.logger.info('[MON]    flusso %s -> %s: %.1f Mbit/s',
                                 host_ip(src), host_ip(dst), rate / 1000000)

    # MODULO 3: DETECTION. Legge le misure del Monitoraggio e decide.
    def detection(self):
        while True:
            hub.sleep(DETECT_INTERVAL)
            now = time.time()

            # Tiene traccia dei flussi attivi nello slice UPPER. Un TCP soffocato dal traffico UDP può tacere per qualche secondo: per questo ricordiamo l'ultimo istante in cui era attivo, e non solo se lo è adesso.
            for pair in list(self.flow_rate):
                if self.flow_rate[pair] > ACTIVE_MIN and pair not in self.on_lower:
                    self.upper_seen[pair] = now

            # Decisioni di policy.json: un flusso nella lista lower va su LOWER subito, qualunque sia il rate.
            for pair in self.policy['lower']:
                if pair not in self.on_lower and pair in self.flow_rate:   # solo i flussi che passano da s4/s5
                    self.logger.info('[DET] %s -> %s: SPOSTATO SU LOWER dall\'amministratore',
                                     host_ip(pair[0]), host_ip(pair[1]))
                    self.on_lower.append(pair)
                    self.under_count[pair] = 0
                    self.orders.put(('move', pair))
            # un flusso in allow che si trovi su LOWER torna subito su UPPER
            for pair in self.policy['allow']:
                if pair in self.on_lower and pair not in self.policy['lower']:
                    self.logger.info('[DET] %s -> %s: RIAMMESSO SU UPPER dall\'amministratore (allow)',
                                     host_ip(pair[0]), host_ip(pair[1]))
                    self.on_lower.remove(pair)
                    self.orders.put(('readmit', pair))

            for access in ACCESS_SWITCHES:    # il link verso ogni switch di accesso può congestionarsi

                # Viene calcolato il numero N di flussi attivi su UPPER negli ultimi ACTIVE_WINDOW secondi
                upper_flows = []
                for src, dst in list(self.upper_seen):
                    recent = now - self.upper_seen[(src, dst)] < ACTIVE_WINDOW
                    if host_switch(dst) == access and recent and (src, dst) not in self.on_lower:
                        upper_flows.append((src, dst))
                n = len(upper_flows)

                # Il link da s4 verso quello switch è congestionato se supera l'80% della capacità
                congested = access in self.link_rate and self.link_rate[access] > CONGESTION_LEVEL * UPPER_CAPACITY

                # Chi supera FAIR_FACTOR (2) volte la sua parte equa per DETECT_SECONDS di fila
                if n > 0:
                    fair_share = UPPER_CAPACITY / n          # la parte equa: capacità divisa per N
                    threshold = FAIR_FACTOR * fair_share
                    for src, dst in upper_flows:
                        pair = (src, dst)
                        if pair in self.policy['allow']:
                            continue                         # i flussi in allow non vengono mai controllati
                        if pair not in self.over_count:
                            self.over_count[pair] = 0
                        if congested and self.flow_rate[pair] > threshold:
                            self.over_count[pair] = self.over_count[pair] + 1
                        else:
                            self.over_count[pair] = 0        # basta un secondo sotto e si riparte da zero
                        if self.over_count[pair] >= DETECT_SECONDS:
                            self.logger.info('[DET] %s -> %s: %.1f Mbit/s > soglia %.1f (N=%d) da %d s -> SPOSTATO SU LOWER',
                                             host_ip(src), host_ip(dst), self.flow_rate[pair] / 1000000,
                                             threshold / 1000000, n, DETECT_SECONDS)
                            self.on_lower.append(pair)
                            self.over_count[pair] = 0
                            self.under_count[pair] = 0
                            self.orders.put(('move', pair))

                # Riammissione: un flusso su LOWER torna su UPPER se, rientrando,
                # starebbe dentro la sua parte equa (capacita' divisa per N+1).
                back_share = UPPER_CAPACITY / (n + 1)
                for src, dst in list(self.on_lower):
                    pair = (src, dst)
                    if host_switch(dst) != access:
                        continue
                    if pair in self.policy['lower']:
                        continue                    # deciso dall'amministratore: niente riammissione automatica
                    if self.flow_rate[pair] < back_share:
                        self.under_count[pair] = self.under_count[pair] + 1
                    else:
                        self.under_count[pair] = 0
                    if self.under_count[pair] >= RELEASE_SECONDS:
                        self.logger.info('[DET] %s -> %s: %.1f Mbit/s < %.1f da %d s -> RIAMMESSO SU UPPER',
                                         host_ip(src), host_ip(dst), self.flow_rate[pair] / 1000000,
                                         back_share / 1000000, RELEASE_SECONDS)
                        self.on_lower.remove(pair)
                        self.orders.put(('readmit', pair))

    # MODULO 4: ENFORCEMENT, l'unico modulo che scrive regole sugli switch (oltre all'installazione iniziale). Agisce sempre sullo switch di accesso d'ingresso del flusso.

    def enforcement(self):
        while True:
            order, pair = self.orders.get()     # aspetta finchè non arriva un ordine
            src, dst = pair
            datapath = self.datapaths[host_switch(src)]   # switch di accesso d'ingresso (dpid = suo numero)
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_src=src, eth_dst=dst)

            if order == 'move' or order == 'readmit':
                if order == 'move':
                    out_port = PORT_LOWER       # porta 2: verso s5, slice LOWER
                    where = 's5, slice LOWER'
                else:
                    out_port = PORT_UPPER       # porta 1: verso s4, slice UPPER
                    where = 's4, slice UPPER'
                # Stessa regola (stesso match, stessa priorità), nuova uscita.
                # MODIFY_STRICT cambia solo le azioni e NON azzera i contatori: si continua a monitorare.
                actions = [parser.OFPActionOutput(out_port)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_MODIFY_STRICT,
                                        priority=PRIO_FORWARD, match=match, instructions=inst)
                datapath.send_msg(mod)
                self.logger.info('[ENF] s%d: %s -> %s ora esce dalla porta %d (%s)',
                                 datapath.id, host_ip(src), host_ip(dst), out_port, where)

            elif order == 'block':
                # Vince sulla regola di coppia (priorità 10), che resta li' sotto intatta.
                self.add_flow(datapath, PRIO_BLOCK, match, [])
                self.logger.info('[ENF] s%d: %s -> %s BLOCCATO (regola di scarto, priorita\' %d)',
                                 datapath.id, host_ip(src), host_ip(dst), PRIO_BLOCK)

            elif order == 'unblock':
                # Tolgo solo la regola di scarto: torna a valere la regola di coppia.
                mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE_STRICT,
                                        priority=PRIO_BLOCK, match=match,
                                        out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
                datapath.send_msg(mod)
                self.logger.info('[ENF] s%d: %s -> %s sbloccato (regola di scarto tolta)',
                                 datapath.id, host_ip(src), host_ip(dst))


    # MODULO 5: POLICY. Ogni secondo rilegge policy.json: è la struttura attraverso cui l'amministratore contribuisce alle decisioni.
    def policy_reader(self):
        while True:
            hub.sleep(POLICY_INTERVAL)
            # Aspetta che tutti gli switch siano collegati, altrimenti non saprebbe dove scrivere le regole.
            connected = True
            for dpid in ACCESS_SWITCHES + [UPPER_SWITCH, LOWER_SWITCH]:
                if dpid not in self.datapaths:
                    connected = False
            if connected:
                self.check_policy()

    def check_policy(self):
        #  se il file manca o è scritto male, open() o json.load() sollevano un'eccezione: la catturiamo nell'except
        try:
            f = open(POLICY_FILE)
            data = json.load(f)                 # il testo JSON diventa un dizionario Python
            f.close()
            if data == self.policy_raw:
                return                          # se il file non è cambiato dall'ultima lettura non si fa niente
            new_policy = {'block': [], 'allow': [], 'lower': []}
            
            for kind in new_policy:                                 # le tre liste (block, allow, lower)
                for src_ip, dst_ip in data.get(kind, []):           # ogni regola è una coppia di IP
                    src, dst = host_mac(src_ip), host_mac(dst_ip)   # le regole OpenFlow lavorano sui MAC
                    if src and dst:
                        new_policy[kind].append((src, dst))
                    else:
                        self.logger.info('[POL] %s -> %s: IP che non fa parte della rete, ignorato', src_ip, dst_ip)
        
        except Exception as error:
            if str(error) != self.policy_error:     # lo scrivo una volta sola, non ogni secondo
                self.logger.info('[POL] policy.json non leggibile (%s): resta valida la policy precedente', error)
                self.policy_error = str(error)
            return
        self.policy_error = ''
        self.policy_raw = data

        # Confronto i blocchi nuovi con quelli vecchi (gli ordini vengono mandati all'Enforcement)
        for pair in new_policy['block']:
            if pair not in self.policy['block']:
                self.orders.put(('block', pair))
        for pair in self.policy['block']:
            if pair not in new_policy['block']:
                self.orders.put(('unblock', pair))

        self.policy = new_policy                # da adesso si vede la policy nuova
        self.logger.info('[POL] nuova policy: %s', data)
