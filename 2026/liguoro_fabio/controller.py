#!/usr/bin/python3
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                    DEAD_DISPATCHER, set_ev_cls)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

# Identificativi degli switch
DPID_S1 = 1          # switch di ingresso
DPID_S2 = 2          # percorso primario
DPID_S3 = 3          # percorso secondario
DPID_S4 = 4          # switch di uscita

# Numerazione delle porte
S1_PORT_PRIMARY = 3      # s1 -> s2
S1_PORT_SECONDARY = 4    # s1 -> s3
S4_PORT_PRIMARY = 3      # s4 -> s2
S4_PORT_SECONDARY = 4    # s4 -> s3

# Indirizzamento
H1, H2, H3, H4 = '10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4'

# Priorita' delle flow entry
PRIO_ROUTING = 20        # match su (ipv4_src, ipv4_dst)
PRIO_DELIVERY = 10       # match sul solo ipv4_dst
PRIO_TABLE_MISS = 0      # entry di default

# Parametri del monitoraggio
MONITOR_PERIOD = 2.0             # intervallo di polling in secondi
LINK_CAPACITY_BPS = 10 * 10**6   # capacita' di un link di core 10 Mbps

# Soglie della politica di controllo
THRESHOLD_HIGH = 0.80    # sopra l'80% -> serve un secondo percorso
THRESHOLD_LOW = 0.30     # sotto il 30% -> un solo percorso e' sufficiente

# Numero di campioni consecutivi che devono confermare la condizione
CONFIRM_SAMPLES = 2

# Output
CSV_PATH = '/tmp/te_monitor.csv'

# Stati della macchina a stati
STATE_CONSOLIDATED = 'CONSOLIDATED'  # entrambi i flussi sul primario
STATE_SPLIT = 'SPLIT'                # flusso sul secondario


class AdaptiveTrafficEngineering(app_manager.RyuApp):
    """Controller SDN con rerouting adattivo basato sul carico dei link."""

    # Dichiara al framework Ryu che questa applicazione parla OpenFlow 1.3.
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AdaptiveTrafficEngineering, self).__init__(*args, **kwargs)

        # Mappa dpid -> oggetto datapath
        self.datapaths = {}

        # (dpid, port_no) -> (tx_bytes, timestamp)
        self.prev_stats = {}

        # Stato corrente della politica di instradamento
        self.state = STATE_CONSOLIDATED

        # Contatori di conferma delle due condizioni
        self.high_count = 0
        self.low_count = 0

        # Istante di avvio, per avere timestamp relativi nel CSV
        self.t0 = time.time()

        # File CSV con le misure (Presentation Layer)
        self.csv = open(CSV_PATH, 'w')
        self.csv.write('t,thr_primary_mbps,thr_secondary_mbps,'
                       'thr_total_mbps,utilization,state\n')
        self.csv.flush()

        # esegue il ciclo di monitoraggio in parallelo alla gestione degli
        # eventi OpenFlow
        self.monitor_thread = hub.spawn(self._monitor_loop)

        self.logger.info('=== Adaptive TE controller avviato ===')
        self.logger.info('Soglie: HIGH=%.2f LOW=%.2f, conferma su %d campioni',
                         THRESHOLD_HIGH, THRESHOLD_LOW, CONFIRM_SAMPLES)

    # GESTIONE DELLA CONNESSIONE DEGLI SWITCH

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER: # lo switch ha completato l'handshake ed e' operativo
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.logger.info('Switch connesso: dpid=%d', datapath.id)
        elif ev.state == DEAD_DISPATCHER: # la connessione con lo switch e' caduta.
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.warning('Switch disconnesso: dpid=%d', datapath.id)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Invocato alla ricezione del messaggio Features Reply, cioe' subito
        dopo l'handshake OpenFlow. E' il momento in cui popoliamo la flow
        table dello switch: siamo in modalita' PROATTIVA, quindi le regole
        vengono installate PRIMA che arrivi il primo pacchetto di traffico.
        """
        datapath = ev.msg.datapath
        dpid = datapath.id

        self._install_table_miss(datapath)

        if dpid == DPID_S1:
            self._program_s1(datapath)
        elif dpid in (DPID_S2, DPID_S3):
            self._program_transit(datapath)
        elif dpid == DPID_S4:
            self._program_s4(datapath)
        else:
            self.logger.warning('dpid sconosciuto: %d (nessuna regola)', dpid)

    # INSTALLAZIONE DELLE FLOW ENTRY

    def _add_flow(self, datapath, priority, match, out_port):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        # Azione: inoltra il pacchetto sulla porta indicata.
        actions = [parser.OFPActionOutput(out_port)]
        # APPLY_ACTIONS fa eseguire subito le azioni senza accodarle all'action set.
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=0,
            priority=priority,
            match=match,
            instructions=inst,
            command=ofp.OFPFC_ADD
        )
        datapath.send_msg(mod)

    def _install_table_miss(self, datapath):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()  # nessun campo specificato = wildcard totale
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, 64)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath, table_id=0,
                                priority=PRIO_TABLE_MISS, match=match,
                                instructions=inst, command=ofp.OFPFC_ADD)
        datapath.send_msg(mod)

    def _program_s1(self, datapath):
        parser = datapath.ofproto_parser

        # Flusso A: h1 -> h3
        self._add_flow(
            datapath, PRIO_ROUTING,
            parser.OFPMatch(eth_type=0x0800, ipv4_src=H1, ipv4_dst=H3),
            S1_PORT_PRIMARY)

        # Flusso B: h2 -> h4
        self._add_flow(
            datapath, PRIO_ROUTING,
            parser.OFPMatch(eth_type=0x0800, ipv4_src=H2, ipv4_dst=H4),
            S1_PORT_PRIMARY)

        # Consegna locale del traffico di ritorno
        self._add_flow(datapath, PRIO_DELIVERY,
                       parser.OFPMatch(eth_type=0x0800, ipv4_dst=H1), 1)
        self._add_flow(datapath, PRIO_DELIVERY,
                       parser.OFPMatch(eth_type=0x0800, ipv4_dst=H2), 2)

        self.logger.info('s1 programmato: entrambi i flussi sul primario')

    def _program_transit(self, datapath):
        parser = datapath.ofproto_parser

        # Verso s1 (porta 1): destinazioni h1 e h2
        for ip in (H1, H2):
            self._add_flow(datapath, PRIO_DELIVERY,
                           parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip), 1)

        # Verso s4 (porta 2): destinazioni h3 e h4
        for ip in (H3, H4):
            self._add_flow(datapath, PRIO_DELIVERY,
                           parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip), 2)

        self.logger.info('s%d programmato (nodo di transito)', datapath.id)

    def _program_s4(self, datapath):
        parser = datapath.ofproto_parser

        # Ritorno del flusso A: h3 -> h1
        self._add_flow(
            datapath, PRIO_ROUTING,
            parser.OFPMatch(eth_type=0x0800, ipv4_src=H3, ipv4_dst=H1),
            S4_PORT_PRIMARY)

        # Ritorno del flusso B: h4 -> h2
        self._add_flow(
            datapath, PRIO_ROUTING,
            parser.OFPMatch(eth_type=0x0800, ipv4_src=H4, ipv4_dst=H2),
            S4_PORT_PRIMARY)

        # Consegna locale verso gli host destinatari
        self._add_flow(datapath, PRIO_DELIVERY,
                       parser.OFPMatch(eth_type=0x0800, ipv4_dst=H3), 1)
        self._add_flow(datapath, PRIO_DELIVERY,
                       parser.OFPMatch(eth_type=0x0800, ipv4_dst=H4), 2)

        self.logger.info('s4 programmato: entrambi i flussi sul primario')

    # RILEVAZIONE DEL TRAFFICO IMPREVISTO

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self.logger.debug('Table-miss su dpid=%d (pacchetto scartato)',
                          ev.msg.datapath.id)
        
    # MONITORAGGIO PERIODICO  (Collection Layer)

    def _monitor_loop(self):
        while True:
            datapath = self.datapaths.get(DPID_S1)
            if datapath is not None:
                self._request_port_stats(datapath)
            hub.sleep(MONITOR_PERIOD)

    def _request_port_stats(self, datapath):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        # OFPP_ANY = chiedi le statistiche di tutte le porte.
        req = parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        if dpid != DPID_S1:
            return

        now = time.time()
        throughput = {}   # port_no -> bit/s

        for stat in ev.msg.body:
            port = stat.port_no
            # Ci interessano solo le due porte che affacciano sui percorsi
            if port not in (S1_PORT_PRIMARY, S1_PORT_SECONDARY):
                continue

            key = (dpid, port)
            prev = self.prev_stats.get(key)
            # tx_bytes = byte trasmessi dalla porta
            self.prev_stats[key] = (stat.tx_bytes, now)

            if prev is None:
                # Prima lettura: non c'e' un termine di paragone
                throughput[port] = 0.0
                continue

            prev_bytes, prev_time = prev
            delta_bytes = stat.tx_bytes - prev_bytes
            delta_time = now - prev_time
            if delta_time <= 0:
                throughput[port] = 0.0
            else:
                throughput[port] = (delta_bytes * 8.0) / delta_time

        if len(throughput) < 2:
            return   # risposta incompleta, saltiamo questo campione

        self._evaluate_policy(throughput[S1_PORT_PRIMARY],
                              throughput[S1_PORT_SECONDARY])

    # VALUTAZIONE DELLA POLITICA  (Analysis Layer)

    def _evaluate_policy(self, thr_primary, thr_secondary):
        total = thr_primary + thr_secondary
        utilization = total / float(LINK_CAPACITY_BPS)
        t_rel = time.time() - self.t0

        self.logger.info(
            '[t=%6.1fs] primario=%5.2f Mbps  secondario=%5.2f Mbps  '
            'U=%5.1f%%  stato=%s',
            t_rel, thr_primary / 1e6, thr_secondary / 1e6,
            utilization * 100, self.state)

        self.csv.write('%.2f,%.4f,%.4f,%.4f,%.4f,%s\n' % (
            t_rel, thr_primary / 1e6, thr_secondary / 1e6,
            total / 1e6, utilization, self.state))
        self.csv.flush()

        # Condizione di CONGESTIONE
        if self.state == STATE_CONSOLIDATED:
            if utilization > THRESHOLD_HIGH:
                self.high_count += 1
                self.logger.info('  soglia alta superata (%d/%d)',
                                 self.high_count, CONFIRM_SAMPLES)
            else:
                # Un solo campione sotto soglia azzera il conteggio
                self.high_count = 0

            if self.high_count >= CONFIRM_SAMPLES:
                self._reroute(to_secondary=True)
                self.state = STATE_SPLIT
                self.high_count = 0
                self.low_count = 0

        # Condizione di RIENTRO
        elif self.state == STATE_SPLIT:
            if utilization < THRESHOLD_LOW:
                self.low_count += 1
                self.logger.info('  soglia bassa superata (%d/%d)',
                                 self.low_count, CONFIRM_SAMPLES)
            else:
                self.low_count = 0

            if self.low_count >= CONFIRM_SAMPLES:
                self._reroute(to_secondary=False)
                self.state = STATE_CONSOLIDATED
                self.high_count = 0
                self.low_count = 0

    # AZIONE DI RECONFIGURAZIONE

    def _reroute(self, to_secondary):
        if to_secondary:
            s1_port, s4_port = S1_PORT_SECONDARY, S4_PORT_SECONDARY
            label = 'SECONDARIO (s1-s3-s4)'
        else:
            s1_port, s4_port = S1_PORT_PRIMARY, S4_PORT_PRIMARY
            label = 'PRIMARIO (s1-s2-s4)'

        self.logger.info('>>> REROUTE: flusso h2<->h4 spostato su %s', label)

        # Direzione di andata: h2 -> h4
        dp1 = self.datapaths.get(DPID_S1)
        if dp1 is not None:
            match = dp1.ofproto_parser.OFPMatch(
                eth_type=0x0800, ipv4_src=H2, ipv4_dst=H4)
            self._modify_flow(dp1, PRIO_ROUTING, match, s1_port)

        # Direzione di ritorno: h4 -> h2
        dp4 = self.datapaths.get(DPID_S4)
        if dp4 is not None:
            match = dp4.ofproto_parser.OFPMatch(
                eth_type=0x0800, ipv4_src=H4, ipv4_dst=H2)
            self._modify_flow(dp4, PRIO_ROUTING, match, s4_port)

    def _modify_flow(self, datapath, priority, match, out_port):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=0,
            priority=priority,
            match=match,
            instructions=inst,
            command=ofp.OFPFC_MODIFY_STRICT
        )
        datapath.send_msg(mod)
