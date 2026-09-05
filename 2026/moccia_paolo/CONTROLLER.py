import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

SERVER = '10.0.0.4'  # h4
CLIENTS = ['10.0.0.1', '10.0.0.2', '10.0.0.3']   # h1, h2, h3

# Switch di accesso di ogni host.

ACCESS_SWITCH = {
    '10.0.0.1': 1,
    '10.0.0.2': 1,
    '10.0.0.3': 2,
    '10.0.0.4': 4,
}

# Tabella di inoltro (IP sorgente, IP destinazione, porta di uscita).

ROUTES = {
    1: [
        ('10.0.0.1', '10.0.0.4', 3),
        ('10.0.0.4', '10.0.0.1', 1),
        ('10.0.0.2', '10.0.0.4', 3),
        ('10.0.0.4', '10.0.0.2', 2),
    ],
    2: [
        ('10.0.0.3', '10.0.0.4', 3),
        ('10.0.0.4', '10.0.0.3', 1),
    ],
    3: [
        ('10.0.0.1', '10.0.0.4', 3),
        ('10.0.0.4', '10.0.0.1', 1),
        ('10.0.0.2', '10.0.0.4', 3),
        ('10.0.0.4', '10.0.0.2', 1),
        ('10.0.0.3', '10.0.0.4', 3),
        ('10.0.0.4', '10.0.0.3', 2),
    ],
    4: [
        ('10.0.0.1', '10.0.0.4', 2),
        ('10.0.0.4', '10.0.0.1', 1),
        ('10.0.0.2', '10.0.0.4', 2),
        ('10.0.0.4', '10.0.0.2', 1),
        ('10.0.0.3', '10.0.0.4', 2),
        ('10.0.0.4', '10.0.0.3', 1),
    ],
}

# Parametri

POLL_INTERVAL = 3.0        # intervallo di campionamento (s)
BOTTLENECK_MBPS = 10       # capacita' del link s4-h4;
ACTIVE_MIN_MBPS = 0.05     
FAIR_FACTOR = 1.5          
CONFIRM_BLOCK = 2          # intervalli consecutivi richiesti per il blocco
BLOCK_DURATIONS = [60, 120, 300]  
NORMALE = 'NORMALE'
BLOCCATO = 'BLOCCATO'
PRIO_TABLE_MISS = 0     # cio' che non ha match va al controller
PRIO_NOISE = 1          # scarto del traffico IPv6 
PRIO_ARP = 5           
PRIO_FORWARD = 10       # rotte statiche 
PRIO_BLOCK = 100        

class FlowState(object):
    """Stato della macchina per un singolo flusso client -> server."""

    def __init__(self):
        self.state = NORMALE
        self.block_count = 0      # intervalli consecutivi in condizione di blocco
        self.blocked_at = 0.0
        self.strikes = 0          # numero di blocchi subiti (recidiva)

    def block_duration(self):
        idx = min(self.strikes, len(BLOCK_DURATIONS)) - 1
        return BLOCK_DURATIONS[max(idx, 0)]


class NCIController(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #Inizializzazione controller ed avvio del thread di monitoraggio
    def __init__(self, *args, **kwargs):
        super(NCIController, self).__init__(*args, **kwargs)
        self.datapaths = {}          
        self.samples = {}            
        self.rates = {}              
        self.flows = dict((c, FlowState()) for c in CLIENTS)
        self.monitor_thread = hub.spawn(self._monitor)

    #Aggiornamento switch raggiungibili 
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER and datapath.id in self.datapaths:
            self.logger.info("[DISCONNECT] s%s non piu' raggiungibile", datapath.id)
            del self.datapaths[datapath.id]

    #Installazione delle regole di base e della tabella di inoltro proattiva
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id

        if dpid not in ROUTES:
            self.logger.warning("[CONNECT] switch sconosciuto dpid=%s, ignorato", dpid)
            return

        self.datapaths[dpid] = datapath

        self._install_baseline(datapath)
        n = self._install_routes(datapath)
        self.logger.info("[CONNECT] s%s connesso, %d rotte installate", dpid, n)

    #Regole comuni ad ogni switch(Table Mis,Arp)
    def _install_baseline(self, datapath):
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss
        self.add_flow(datapath, PRIO_TABLE_MISS,
                      parser.OFPMatch(),
                      [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)])

        # IPv6 scartato 
        self.add_flow(datapath, PRIO_NOISE,
                      parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6),
                      [])

        # ARP 
        self.add_flow(datapath, PRIO_ARP,
                      parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP),
                      [parser.OFPActionOutput(ofproto.OFPP_FLOOD)])

    #Installazione rotte statiche per ogni coppia client server 
    def _install_routes(self, datapath):
        
        parser = datapath.ofproto_parser
        dpid = datapath.id

        for src_ip, dst_ip, out_port in ROUTES[dpid]:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_src=src_ip,
                                    ipv4_dst=dst_ip)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, PRIO_FORWARD, match, actions)

            self.logger.debug("  [ROUTE] s%s  %s -> %s  out:%s",
                              dpid, src_ip, dst_ip, out_port)

        return len(ROUTES[dpid])

    #Invio allo switch una regola da installare 
    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                instructions=inst,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    #Rimuove dallo switch una regola 
    def del_flow(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE_STRICT,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                priority=priority,
                                match=match)
        datapath.send_msg(mod)

    #Individuazione del match del flusso attacante 
    def _block_match(self, datapath, client):
        parser = datapath.ofproto_parser
        return parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                               ipv4_src=client,
                               ipv4_dst=SERVER)

    #Installazione del drop sullo switch di accesso dell'attacante
    def _apply_block(self, client, reason):
        
        dpid = ACCESS_SWITCH[client]
        datapath = self.datapaths.get(dpid)
        if datapath is None:
            self.logger.warning("[BLOCK] s%s non raggiungibile, blocco non applicato", dpid)
            return False

        self.add_flow(datapath, PRIO_BLOCK,
                      self._block_match(datapath, client), [])

        fs = self.flows[client]
        fs.strikes += 1
        fs.blocked_at = time.time()
        self.logger.info("[BLOCK] s%s  drop %s -> %s  per %ds  (%s)",
                         dpid, client, SERVER, fs.block_duration(), reason)
        return True

    #Rimozione del drop allo scadere del timer
    def _remove_block(self, client):
        dpid = ACCESS_SWITCH[client]
        datapath = self.datapaths.get(dpid)
        if datapath is None:
            return

        self.del_flow(datapath, PRIO_BLOCK, self._block_match(datapath, client))
        self.logger.info("[UNBLOCK] s%s  rimosso drop %s -> %s",
                         dpid, client, SERVER)

    #Interroga gli switch per valutarne i rate ad ogni intervallo
    def _monitor(self):
        
        hub.sleep(POLL_INTERVAL)          

        while True:
            polled = sorted(self.datapaths.keys())
            for datapath in list(self.datapaths.values()):
                self._request_stats(datapath)

            hub.sleep(POLL_INTERVAL)
            self._evaluate(polled)

    #Richiesta delle statistiche delle flow entry di uno switch
    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowStatsRequest(datapath))

    #Riceve le statistiche e ne ricava il rate dalla differenze tra due letture consecutive
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        
        dpid = ev.msg.datapath.id
        now = time.time()

        for stat in ev.msg.body:
            if stat.priority != PRIO_FORWARD:
                continue

            fields = dict(stat.match.items())
            src = fields.get('ipv4_src')
            dst = fields.get('ipv4_dst')
            if src is None or dst is None:
                continue

            key = (dpid, src, dst)
            previous = self.samples.get(key)
            self.samples[key] = (stat.byte_count, now)

            if previous is None:
                continue          

            prev_bytes, prev_time = previous
            elapsed = now - prev_time
            delta = stat.byte_count - prev_bytes

            if elapsed <= 0 or delta < 0:
                self.rates[key] = 0.0
                continue

            self.rates[key] = (delta * 8.0) / elapsed / 1e6

    #Calcola la soglia di equità,verifica la condizone di blocco e gestisce le transizioni
    def _evaluate(self, polled):
        now = time.time()

        measured = {}
        for client in CLIENTS:
            dpid = ACCESS_SWITCH[client]
            measured[client] = self.rates.get((dpid, client, SERVER), 0.0)

        active = [c for c in CLIENTS if measured[c] >= ACTIVE_MIN_MBPS]
        n_active = max(len(active), 1)
        threshold = FAIR_FACTOR * BOTTLENECK_MBPS / n_active
        contention = len(active) >= 2
        total = sum(measured.values())

        self.logger.info(
            "[MONITORAGGIO] polled=%s attivi=%d totale=%.2f soglia=%.2f contesa=%s",
            polled, len(active), total, threshold, "si" if contention else "no")

        for client in CLIENTS:
            fs = self.flows[client]
            rate = measured[client]

            # Sblocco a scadenza. Non puo' essere a soglia: con il drop attivo
            # il rate misurato e' 0, quindi si oscillerebbe fra i due stati.
            if fs.state == BLOCCATO:
                if now - fs.blocked_at >= fs.block_duration():
                    self._remove_block(client)
                    self._transition(client, NORMALE, "scadenza del blocco")
                    fs.block_count = 0
                else:
                    self.logger.info("      %s  BLOCCATO  residuo %.0fs",
                                     client, fs.block_duration() - (now - fs.blocked_at))
                continue

            over = rate > threshold

            if over and contention:
                fs.block_count += 1
            else:
                fs.block_count = 0

            if fs.block_count >= CONFIRM_BLOCK:
                reason = "sopra la quota equa sotto contesa"
                if self._apply_block(client, reason):
                    self._transition(client, BLOCCATO, reason)

            self.logger.info("      %s  %6.2f Mbps  %s",
                             client, rate, fs.state)

        for (dpid, src, dst), rate in sorted(self.rates.items()):
            self.logger.debug("      [ALL] s%s  %s -> %s  %6.2f Mbps",
                              dpid, src, dst, rate)


    def _transition(self, client, new_state, reason):
        fs = self.flows[client]
        if fs.state == new_state:
            return
        self.logger.info("[STATE] %s  %s -> %s  (%s)",
                         client, fs.state, new_state, reason)
        fs.state = new_state

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.logger.info("[MISS] s%s in:%s ethertype=0x%04x %s -> %s",
                         dpid, in_port, eth.ethertype, eth.src, eth.dst)
