#!/usr/bin/env python3
"""
Controller SDN per il service slicing.

Applicazione del framework Ryu che svolge tre compiti:

  1. installa in modo PROATTIVO le regole di slicing appena lo switch di
     accesso si collega, prima che transiti qualunque traffico;
  2. inoltra il resto del traffico con apprendimento degli indirizzi MAC;
  3. raccoglie periodicamente le statistiche e le scrive su file CSV.


Le code devono essere gia' state create da topology.py.

Uso:
    ryu-manager slicing_controller.py
    SLICING_MODE=none SLICING_CSV=base.csv ryu-manager slicing_controller.py
"""

import csv
import os
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                    DEAD_DISPATCHER, set_ev_cls)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types

#Costanti

# Solo s1 ha le code configurate: su s2 assegnare una coda inesistente
# farebbe scartare i pacchetti.
DPID_CON_QOS = 1

PORTA_COLLO_BOTTIGLIA = 4       # porta di s1 verso s2
IP_SERVER = '10.0.0.100'        # destinazione comune dei tre flussi

INTERVALLO_POLLING = 1          # secondi fra due richieste di statistiche

PRIO_TABLE_MISS = 0
PRIO_APPRENDIMENTO = 1
PRIO_SLICING = 10               # deve vincere sulle regole di apprendimento

# Definizione degli slice.
#   cookie -> etichetta con cui ritroviamo il flusso nelle statistiche
#   coda   -> deve corrispondere alle code create in topology.py
SLICES = {
    1: {'nome': 'video', 'coda': 1, 'proto': 'udp', 'porta': 5004},
    2: {'nome': 'iot',   'coda': 2, 'proto': 'udp', 'porta': 1883},
    3: {'nome': 'bulk',  'coda': 0, 'proto': 'tcp', 'porta': 80},
    4: {'nome': 'probe', 'coda': 1, 'proto': 'icmp', 'porta': None},
}

CSV_PATH = os.environ.get('SLICING_CSV', 'stats.csv')

# Scenario di esecuzione, deve concordare con l'opzione --qos di topology.py.
#   'slicing' -> il traffico viene assegnato alle tre code differenziate
#   'none'    -> nessuna assegnazione, tutto resta nella coda di default
# Le regole vengono installate in entrambi gli scenari: i cookie servono a
# misurare il throughput per slice anche nel caso di riferimento.
MODO = os.environ.get('SLICING_MODE', 'slicing')


class SlicingController(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SlicingController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.byte_precedenti = {}
        self.tx_precedenti = None
        self.t_inizio = time.time()
        self._apri_csv()
        self.thread_monitor = hub.spawn(self._monitor)

    #CSV

    def _apri_csv(self):
        self.csv_file = open(CSV_PATH, 'w')
        self.csv = csv.writer(self.csv_file)
        self.csv.writerow(['t', 'slice', 'byte_totali', 'mbps', 'pacchetti'])
        self.csv_file.flush()
        self.logger.info("Modalita': %s", MODO)
        self.logger.info('Statistiche scritte su %s', os.path.abspath(CSV_PATH))

    #Gestione datapath

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _cambio_stato(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_collegato(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser

        # regola di default: cio' che non trova corrispondenza va al controller
        self._aggiungi_flusso(
            dp, PRIO_TABLE_MISS, parser.OFPMatch(),
            [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])

        self.logger.info('Switch %d collegato', dp.id)

        if dp.id == DPID_CON_QOS:
            self._installa_policy(dp)

    def _aggiungi_flusso(self, dp, priorita, match, azioni,
                         cookie=0, idle=0):
        parser = dp.ofproto_parser
        istruzioni = [parser.OFPInstructionActions(
            dp.ofproto.OFPIT_APPLY_ACTIONS, azioni)]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=priorita, match=match,
            instructions=istruzioni, cookie=cookie, idle_timeout=idle))

    #Policy slicing

    def _match_slice(self, parser, definizione):
        """Match per uno slice: traffico IP diretto al server, con il
        protocollo e la porta di trasporto che identificano la classe.

        Il vincolo sull'indirizzo di destinazione e' necessario: senza,
        la regola ICMP catturerebbe anche i ping fra host di accesso,
        inoltrandoli erroneamente verso il collo di bottiglia.
        """
        base = dict(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=IP_SERVER)
        if definizione['proto'] == 'icmp':
            return parser.OFPMatch(ip_proto=1, **base)
        if definizione['proto'] == 'udp':
            return parser.OFPMatch(ip_proto=17,
                                   udp_dst=definizione['porta'], **base)
        return parser.OFPMatch(ip_proto=6,
                               tcp_dst=definizione['porta'], **base)

    def _installa_policy(self, dp):
        parser = dp.ofproto_parser
        self.logger.info('Installazione della policy di slicing su s%d', dp.id)

        for cookie, d in sorted(SLICES.items()):
            if MODO == 'slicing':
                # SetQueue deve precedere Output: le azioni sono ordinate
                azioni = [parser.OFPActionSetQueue(d['coda']),
                          parser.OFPActionOutput(PORTA_COLLO_BOTTIGLIA)]
                dove = 'coda %d' % d['coda']
            else:
                azioni = [parser.OFPActionOutput(PORTA_COLLO_BOTTIGLIA)]
                dove = 'coda unica'

            self._aggiungi_flusso(dp, PRIO_SLICING,
                                  self._match_slice(parser, d),
                                  azioni, cookie=cookie)

            porta = d['porta'] if d['porta'] else '-'
            self.logger.info('   %-5s  %-4s %-5s -> %s',
                             d['nome'], d['proto'], porta, dove)

    #Packet handler

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        """Apprendimento degli indirizzi MAC. Il traffico classificato non
        arriva qui: e' gia' coperto dalle regole installate all'avvio."""
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.mac_to_port.setdefault(dp.id, {})
        self.mac_to_port[dp.id][eth.src] = in_port

        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)
        azioni = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            self._aggiungi_flusso(
                dp, PRIO_APPRENDIMENTO,
                parser.OFPMatch(in_port=in_port, eth_dst=eth.dst),
                azioni, idle=30)

        dati = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=azioni, data=dati))

    #Monitoraggio

    def _monitor(self):
        while True:
            dp = self.datapaths.get(DPID_CON_QOS)
            if dp is not None:
                parser = dp.ofproto_parser
                dp.send_msg(parser.OFPFlowStatsRequest(dp))
                dp.send_msg(parser.OFPPortStatsRequest(
                    dp, 0, dp.ofproto.OFPP_ANY))
            hub.sleep(INTERVALLO_POLLING)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _statistiche_flussi(self, ev):
        t = time.time() - self.t_inizio

        # i contatori sono cumulativi: il throughput e' la loro derivata
        per_slice = {}
        for st in ev.msg.body:
            if st.cookie in SLICES:
                agg = per_slice.setdefault(st.cookie, {'byte': 0, 'pkt': 0})
                agg['byte'] += st.byte_count
                agg['pkt'] += st.packet_count

        for ck, agg in sorted(per_slice.items()):
            prec = self.byte_precedenti.get(ck, agg['byte'])
            delta = max(0, agg['byte'] - prec)
            self.byte_precedenti[ck] = agg['byte']
            mbps = (delta * 8.0) / (INTERVALLO_POLLING * 10 ** 6)
            self.csv.writerow(['%.2f' % t, SLICES[ck]['nome'], agg['byte'],
                               '%.3f' % mbps, agg['pkt']])
        self.csv_file.flush()

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _statistiche_porte(self, ev):
        for st in ev.msg.body:
            if st.port_no != PORTA_COLLO_BOTTIGLIA:
                continue
            if self.tx_precedenti is not None:
                delta = st.tx_bytes - self.tx_precedenti
                mbps = (delta * 8.0) / (INTERVALLO_POLLING * 10 ** 6)
                if mbps > 0.01:          # silenzio quando non passa traffico
                    self.logger.info(
                        'collo di bottiglia: %.2f Mbps  scartati %d',
                        mbps, st.tx_dropped)
            self.tx_precedenti = st.tx_bytes
