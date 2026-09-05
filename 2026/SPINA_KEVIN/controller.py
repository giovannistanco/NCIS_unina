from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology import event
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from monitor import TrafficMonitor
from qos import QoSManager

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
    #la struttura per il MAC Learning mantenuta dal controller 
    # ad ogni switch associa un mac a una porta di uscita per raggiungerlo
        self.mac_to_port = {}
    # porte presenti su ciascuno switch, attive e collegate ad altri dispositivi
        self.switch_ports = {}
    # collegamenti tra switch, ci dice che porta usare per andarre da swX a swY
        self.links = {}
    # porte che portano verso altri switch e non verso host/server
        self.link_ports = {}
    #necessario per lo spanning tree per il flood, contiene per ogni switch le porte
    #inter-switch da usare per il flooding
        self.tree_ports = {}
    #indice per round robin, dict perche ne tengo uno per ogni coppia src dst
        self.rr_index = {}
    #dict per tener traccia del path di ogni flow che stiamo gestendo
        self.flow_paths = {}
    #dict che associa ad ogni switch (dpid) il datapath (conn. openflow)
        self.datapaths = {}

        self.monitor = TrafficMonitor(self)

        self.qos = QoSManager()
        self.flow_classes = {}#per ogni flow memorizza HIGH o BE

#RYU gestisce automaticamente la prima fase di connessione con lo switch in cui si scambiano
#HALLO<->HALLO, (controller)FETURE_REQUEST->(switch), FEATURE_REPLAY->(controller)
#una volta ricevuto il replay ryu genera EventOFPSwitchFeatures, quindi il decoratore
#consente di chiamare la funzione sottostante
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath#rappresenta la connessione OF
    #popoliamo questo dict man mano che creiamo conn openflow
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser#x creare obj OF (mex, azioni, match...)

        match = parser.OFPMatch()#non ci sono condizioni di match, matchera con tutti i pacc.
#come azione dico di mandare il pachetto al controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
#installiamo questa flow con priorita 0, intercetta tutti i pacchetti che non pero non hanno
#trovato alcuna regola in precedenza

#quando viene aggiunto uno switch alla topologia, si genera questo evento
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):

        switch = ev.switch #oggetto che rappresenta lo switch nuovo
        dpid = switch.dp.id

        self.switch_ports[dpid] = set()#creiamo un insieme vuoto per questo nuovo switch
        
    #ryu ci fornisce le porte attive del nuovo sw, le prendiamo tutte tranne quelle dedicate
    #a openflow tipo quella per il controller, e le aggiungiamo alle porte di quello switch
        for port in switch.ports:
            if port.port_no < ofproto_v1_3.OFPP_MAX:
                self.switch_ports[dpid].add(port.port_no)


    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
#ryu genera un evento che rappresenta la creazione di un nuovo link TRA SWITCH, fornendo 
#src dst e da quali porte questi son collegati
        src = ev.link.src
        dst = ev.link.dst

#per adnare da src a dst usa la porta src.port_no della sorgente
        self.links[(src.dpid, dst.dpid)] = src.port_no

#se non ho ancora creato l'insieme delle porte inter-switch per questo switch, crealo e ci
#aggiungiamo che questo nuovo link coll.
        self.link_ports.setdefault(src.dpid, set())#se non esiste crea una chiave e assegna set vuoto
        self.link_ports[src.dpid].add(src.port_no)
#per ogni cambio di tipologia ricostruisco l albero di flooding
        self.build_flood_tree()

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        #f. per intercettare le risposte alle richieste di statistiche inviate dal monitor
        self.monitor.handle_port_stats(ev.msg)

    def build_flood_tree(self):
        #f per crare lo spanning tree

        # ricostruisco ogni volta l'albero da zero
        self.tree_ports = {}

        # se non conosco ancora nessuno switch non posso fare niente
        if not self.switch_ports:
            return

        # dizionario: switch -> insieme degli switch direttamente vicini
        neighbors = {}

# ricavo i vicini dalla topologia salvata in self.links
#sfrutto il dizionario self.links che ha come chiavi le coppie (1,2), (1,3), (2,1)...
#scorro le chiavi (coppie src,dst) e per ogni src e dst segno i vicini
        for src, dst in self.links:

            if src not in neighbors:
                neighbors[src] = set()

            if dst not in neighbors:
                neighbors[dst] = set()
#utilizziamo i set poichè non permettono duplicati
            neighbors[src].add(dst)
            neighbors[dst].add(src)
#neighbors avra la topologia della rete sottoforma di dizionario switch(key)->vicini(value)

        # scelgo come radice lo switch con DPID più piccolo
        root = min(self.switch_ports.keys())

        # switch già scoperti dalla BFS
        visited = {root}

        # coda della BFS
        queue = [root]

        i = 0
#finche ci sono switch da visitare cicla
        while i < len(queue):
            #switch da visitare
            current = queue[i]
            i += 1

            # guardo tutti i vicini dello switch che sto visitando e per ognuno...
            for neighbor in sorted(neighbors.get(current, set())):#per orgni vicini dello switch corrente

                # se non l'ho già raggiunto lo esploro
                if neighbor not in visited:
                    # nuovo switch scoperto
                    visited.add(neighbor)
                    queue.append(neighbor)

                    # recupero da self.links le porte delle due estremità
                    port_current = self.links.get((current, neighbor))
                    port_neighbor = self.links.get((neighbor, current))

                    # preparo gli insiemi delle porte dell'albero
                    if current not in self.tree_ports:
                        self.tree_ports[current] = set()

                    if neighbor not in self.tree_ports:
                        self.tree_ports[neighbor] = set()

                    # aggiungo le due porte del link scelto dalla BFS
                    if port_current is not None:
                        self.tree_ports[current].add(port_current)

                    if port_neighbor is not None:
                        self.tree_ports[neighbor].add(port_neighbor)

        if len(self.switch_ports) == 6:
            self.logger.info("FLOOD TREE FINALE: %s", self.tree_ports)

    def get_paths(self, src, dst):
        #funzione per cerca tutti i possibili path da src a dst
        neighbors = {} #dict switch->vicini
    #creiamo la topologia della rete sfruttando le info in self.links

    #per ogni coppia switxh sfruttando src dst in links creo la lista dei vicini
        for switch_src, switch_dst in self.links:
            if switch_src not in neighbors:
                neighbors[switch_src] = set()
            neighbors[switch_src].add(switch_dst)
        paths = []
        stack = [[src]]#contiene i percorsi in fase di costruzione

        while stack:#finche non e vuoto
            path = stack.pop()#al primo ciclo il path è solo lo sw di partenza
            current = path[-1]#l'ultimo switch esplotrato

            if current == dst:
                paths.append(path)#se la dst e raggiunta, path torvato, riparte il while

            else:#per ogni vicino dell'ultimo switch si crea un nuovo path possibile
                for neighbor in neighbors[current]:
                    if neighbor not in path:
                        new_path = path + [neighbor]
                        stack.append(new_path)#lo aggiungo a stack per esplorarlo

        return paths

    def get_path_cost(self, path):
        return len(path) - 1

    def get_path_ports(self, path, dst_port):
    #funzione che, scelto il path, trova grazie a self.links, le porte da usare per ogni switch
        path_ports = {}

        for i in range(len(path) - 1):
            current = path[i]
            next_switch = path[i + 1]

            path_ports[current] = self.links[(current, next_switch)]
    #ultimo seitch deve sucire sulla porta collegata all'host che gia sappiamo
        path_ports[path[-1]] = dst_port

        return path_ports

    def get_host_location(self, mac):
        #f per capire a che switch e colegato un host(ident, con mac) e a quale porta
    #scorrendo gli switch
        for dpid in self.mac_to_port:
            #se questo switch conosce la porta da usare per raggingere il mac prendo la porta
            if mac in self.mac_to_port[dpid]:
                port = self.mac_to_port[dpid][mac]

                # se quella porta NON porta verso un altro switch,
                # allora è una porta host
                if port not in self.link_ports.get(dpid, set()):
                    return (dpid, port)

        return None

    def get_flood_ports(self, dpid, in_port):
        #f che usa il flood tree per capire su che porte inviare il pacchetto in caso di flooding
        
        # tutte le porte presenti sullo switch 
        all_ports = self.switch_ports.get(dpid, set())

        # porte dello switch collegate ad altri switch
        inter_switch_ports = self.link_ports.get(dpid, set())

        # le porte rimanenti sono quelle verso gli host
        host_ports = all_ports - inter_switch_ports

#per il flooding devo usare sia le porte verso host sia le inter-switch del flood tree
        allowed_ports = host_ports | self.tree_ports.get(dpid, set())

        flood_ports = []

        # non devo rimandare il frame sulla porta da cui è arrivato
        for port in sorted(allowed_ports):
            if port != in_port:
                flood_ports.append(port)
        return flood_ports

    def get_flow_id(self, pkt):
        #f per ottenre l'id di un flow

        ip = pkt.get_protocol(ipv4.ipv4)#cerchiamo header ipv4

        if ip is None:
            return None
    #gestiamo solo questi 3 protocolli
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
    #recuperiamo le 5-tuple dall'header così da identificare il flow
        if tcp_pkt is not None:
            return (ip.src, ip.dst, ip.proto, tcp_pkt.src_port, tcp_pkt.dst_port)

        elif udp_pkt is not None:
            return (ip.src, ip.dst, ip.proto, udp_pkt.src_port, udp_pkt.dst_port)

        elif icmp_pkt is not None:
            return (ip.src, ip.dst, ip.proto)
        
        return None

    def select_path(self, src, dst, qos_class):
        # trovo tutti i possibili percorsi tra src e dst
        paths = self.get_paths(src, dst)

        # raggruppo i percorsi in base al costo (chiave) -> paths(valore)
        paths_by_cost = {}

        for path in paths:
            cost = self.get_path_cost(path)
            if cost not in paths_by_cost:
                paths_by_cost[cost] = []
            paths_by_cost[cost].append(path)


        # controllo prima i percorsi col costo più basso,
        # poi eventualmente quelli col costo successivo
        for cost in sorted(paths_by_cost.keys()):
            #candidate contine tutti i path con quel costo (patrtendo dal minore)
            candidate_paths = paths_by_cost[cost]
            available_paths = []

            # tengo solo i path non congestionati di questo livello di costo
            for path in candidate_paths:
                if not self.monitor.is_path_congested(path):
                    available_paths.append(path)


        # se almeno un path di questo costo è disponibile, NON considero percorsi più costosi
            if available_paths:
                key = (src, dst)

                if key not in self.rr_index:
                    self.rr_index[key] = 0#inserisco un indice RR 

                # il numero di path disponibili tra (src,dst) può cambiare a causa della congestione
                #quindi l'indice RR deve essere resettato in base al num dei path disponibili
                #ogni volta che devo scegliere un path
                index = self.rr_index[key] % len(available_paths)

                selected_path = available_paths[index]

                self.rr_index[key] = index + 1

                self.logger.info(
                    " PATH A COSTO MIN (NO CONG.): class%s path%s costo=%s load=%.2f Mbps",
                    qos_class,
                    selected_path,
                    cost,
                    self.monitor.get_path_load(selected_path)
                )

                return selected_path
    #con la qos questa parte (precedente) resta invariata, finche non ho congestione 
    #gestisco il traffico high e BE allo stesso modo mantenendo solo divisione nelle code

            # se tutti i path DI QUESTO COSTO sono congestionati
            # e il flow è high, provo la riserva QoS prima
            # di considerare percorsi più lunghi
            if qos_class == self.qos.HIGH:

                hard_limit = (
                    self.monitor.link_capacity *
                    self.qos.hard_threshold
                )# %calcolata in base alla capacità del link

                admissible_paths = []

                for path in candidate_paths:

                    current_load = self.monitor.get_path_load(path)

                    # carico previsto aggiungendo i Mbps del nuovo flow high
                    projected_load = (
                        current_load +
                        self.qos.high_sla_mbps
                    )

                    # il path di questo costo può ancora accettare high
                    if projected_load <= hard_limit:
                        admissible_paths.append(path)

                if admissible_paths:

                    # tra i path corti ancora ammissibili
                    # scelgo quello meno carico
                    selected_path = min(
                        admissible_paths,
                        key=self.monitor.get_path_load
                    )

                    current_load = self.monitor.get_path_load(selected_path)
                    projected_load = (
                        current_load +
                        self.qos.high_sla_mbps
                    )

                    self.logger.info(
                        "QOS HIGH: PATH %s costo=%s ammesso tramite banda riservata "
                        "load=%.2f projected=%.2f hard_limit=%.2f Mbps",
                        selected_path,
                        cost,
                        current_load,
                        projected_load,
                        hard_limit
                    )

                    return selected_path


        # se TUTTI i percorsi, di qualunque costo, sono congestionati,
        # scelgo quello con carico minore
        selected_path = None
        min_load = None
    #ricerca del  minimo tra tutti i path possibili
        for path in paths:

            load = self.monitor.get_path_load(path)

            if min_load is None or load < min_load:
                min_load = load
                selected_path = path

        self.logger.info(
            "TUTTI I PATH CONGESTIONATI SELEZ. LOAD MIN-> scelto %s load=%.2f Mbps",
            selected_path,
            min_load
        )

        return selected_path

    def build_match(self, datapath, pkt):
    #funzione che serve per creare il match da usare per applicare la regola, non possiamo
    #usare get_flow_id perche qeulla è una struttura python utile al controller, serve
    #una regola openflow, che costruiamo con parser.OFPMatch, è come flowid ma restituisce 
    #un formato openflow da mandare allo switch

        #serve per costruire il messaggio/oggetto openflow e mandarlo allo switch
        parser = datapath.ofproto_parser

        ip = pkt.get_protocol(ipv4.ipv4)#prendiamo header

        if ip is None:
            return None

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
    #chi non è None crea la regola di match
        if tcp_pkt is not None:
            return parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip.src,
                ipv4_dst=ip.dst,
                ip_proto=ip.proto,
                tcp_src=tcp_pkt.src_port,
                tcp_dst=tcp_pkt.dst_port
            )

        elif udp_pkt is not None:
            return parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip.src,
                ipv4_dst=ip.dst,
                ip_proto=ip.proto,
                udp_src=udp_pkt.src_port,
                udp_dst=udp_pkt.dst_port
            )

        elif icmp_pkt is not None:
            return parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip.src,
                ipv4_dst=ip.dst,
                ip_proto=ip.proto
            )

        return None

    def install_path(self, path, dst_port, pkt, qos_class):
    #funzione che crea la regola (e la istanzia nello sw)

        #troviamo tutte le porte da usare sugli switch coinvolti
        path_ports = self.get_path_ports(path, dst_port)
    #installiam ola regola in ogni switch appartenente al path
        for dpid in path:
            #prendiamo la conn OF sfruttando il struttura datapths e preleviamo il parser
            datapath = self.datapaths[dpid]
            parser = datapath.ofproto_parser
        #costruiamo il match (formato OF) da usare per la regola
            match = self.build_match(datapath, pkt)
        #specifichiamo che questo switch per questo flow dovra usare la porta decisa da get_path_ports
            out_port = path_ports[dpid]
        #ricavo l id della coda associata al flow
            queue_id = self.qos.get_queue_id(qos_class)
        #creiamo la relativa azione di output su quella porta
            actions = [ parser.OFPActionSetQueue(queue_id),
                        parser.OFPActionOutput(out_port)]
        #istanziamo uffiacialmente la regola con la f nativa add_flow
            self.add_flow(datapath, 2, match, actions)
#funzione per installare una regola nello switch
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
#con ALLPY_ACTION specifico che le istruzioni da eseguire consistono nell applicare subito le
# azioni specificate in action, con OFPInstructionActions crea un istruzione OF che dice come
#usare le azioni
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:#se lo switch ha il pacchetto nel buffer installa la regola e puo gia gestirlo
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:#creo la regola
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)#la mando esattamente a quello switch (datapath) col 
        #quale ho una connessione oppeflow aperta



        #questa funzione viene chiamata quando il controller riceve un PacketIn da uno switch
        #gia nello stato operativo MAIN_DISPATCHER
   
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        #ev e un evento openflow
    def _packet_in_handler(self, ev):
        #se non e stato ricevuto tutto il pacchetto ...
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']#prendiamo info da dove il pacchetto e entrato

#byte del frame ethernet che vengono trasformati in una struttura interpretabile con packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]#estrae l'header

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignora frame di tipo lddp (per la discovery)
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})#se non esiste una flowtable per sto dpid, creala

        # imparo che su quella porta sta il mac che mi ha appena mandato il pacchetto
        self.mac_to_port[dpid][src] = in_port
        path = None
        #prendiamo traccia di a quali switch sono fisicamente collegati gli host src e dst
        src_location = self.get_host_location(src)
        dst_location = self.get_host_location(dst)

        flow_id = self.get_flow_id(pkt)#identificando quel flow con la 5tupla
        #vediamo / calcoliamo e aggiungiamo la classe di questo flow
        if flow_id is not None:#se ho gia una classe di appartenenza per questo flow
            if flow_id in self.flow_classes:
                qos_class = self.flow_classes[flow_id]
            else:
                qos_class = self.qos.classify_flow(flow_id)
                self.flow_classes[flow_id] = qos_class
                self.logger.info(
                    "NEW FLOW: flow=%s class=%s",
                    flow_id,
                    qos_class
                )

        if src_location is not None and dst_location is not None and flow_id is not None:
        # get_host_location resituisce (dpid, port) ma a noi qui interessa il dpid -> [0]
            src_switch = src_location[0]
            dst_switch = dst_location[0]
#se esiste gia un path per questo flow lo selezioniamo, altrimenti lo calcoliamo con select path
            if flow_id in self.flow_paths:
                path = self.flow_paths[flow_id]

            else:#scegliamo il path per questo nuovo flow
                path = self.select_path(src_switch, dst_switch, qos_class)
                self.flow_paths[flow_id] = path
                #installiamo la regola
                self.install_path(path, dst_location[1], pkt, qos_class)

        if path is not None:
            #get_p_p restituisce un dict switch->porta per raggiungere il next sw del path
            path_ports = self.get_path_ports(path, dst_location[1])
            out_ports = [path_ports[dpid]]#il Dpid dello sw che ha causa packetIn

        elif dst in self.mac_to_port[dpid]:#per gli altri protocolli
            out_ports = [self.mac_to_port[dpid][dst]]

        else:#se non trovo nulla flood
            out_ports = self.get_flood_ports(dpid, in_port)

#bisogna gestire il primo pacchetto del flow (la regola è stata appena installata) con paket_out
#quindi creiamo le azioni usando out_ports che contiene la(o le se flood) porte su cui uscire
        actions = []

        # imposto prima la queue associata alla sua classe
        if path is not None:#path not none solo se il pacchetto appartiene a un flow gestito dal LB/QoS,
            queue_id = self.qos.get_queue_id(qos_class)
            actions.append(parser.OFPActionSetQueue(queue_id))
        #poi inoltro sulla porta scelta per seguire il path
        for port in out_ports:
            actions.append(parser.OFPActionOutput(port))
        #se per qualche motivo il load balancer non ha lavorato (es ARP) allora uso le 
        #conoscenze del controller per gestire questo pacchetto
        if path is None and dst in self.mac_to_port[dpid]:
            #per semplicita di progetto gestiamo con il classico mac learning solo pacchetti ethernet
            #per tcp udp e icmp usiamo i flow, questo perche altrimenti si hanno problemi causati
            #dalle regole installate durante il mac learning
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=eth.ethertype)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
    #SE ESISTE UN BUFF_ID usalo instanzia la regola e ritorna senza fare packetout
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
#OFPPacketOut contruisce un pacchetto OF di tipo packetout e gestiamo il primo pacchetto
#sulla base degli if precedenti
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        #gli dico di apploicare le action a questo pacchetto che poi 
        #è quello che mi ha mandato con packet in
