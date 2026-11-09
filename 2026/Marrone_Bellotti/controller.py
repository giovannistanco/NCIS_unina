# controller.py
#
# DoSController ESTENDE lo switch L2 con STP di Ryu (ryu.app.simple_switch_stp_13):
# eredita forwarding + STP (gestione del ciclo) + table-miss, e AGGIUNGE i moduli
# di monitoring / detection / mitigation. Si avvia da solo:
#
#     PYTHONPATH=. ryu-manager controller.py
#
# (NON va affiancato a simple_switch_stp_13: lo eredita gia', altrimenti due handler
#  packet_in forwarderebbero in doppio degradando il throughput.)
#
# Variabili d'ambiente (tutte opzionali):
#   DETECTOR    ewma (default) | ewma-nohard | ml | ensemble
#   ML_THRESHOLD probabilita' di attacco minima per il ML (default 0.5)
#   MITIGATE    0 = rileva e logga ma non blocca
#   WHITELIST   0 = nessun host protetto (misura dei falsi positivi)
#   CONFIRM     k/n: blocca dopo k intervalli 'attack' sugli ultimi n (default 2/3)
#   CONGESTION  1 = blocca anche il top talker quando un link supera l'80% di utilizzo
#   BLOCK_TTL   secondi dopo cui un blocco scade (default 60, 0 = permanente)
#   FEATURE_LOG path: righe di feature per il dataset ML
#   EVENT_LOG   path: eventi DETECT/BLOCK con timestamp
import os
import time

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import stplib
from ryu.lib.packet import packet, ethernet
from ryu.app import simple_switch_stp_13

from modules.monitor import Monitor
from modules.detector import (AdaptiveThresholdDetector, MLDetector, EnsembleDetector,
                              Confirmer, top_talker)
from modules.features import SourceFeatures
from modules.mitigator import Mitigator
from modules.blocklist import Blocklist

LEGIT = {'00:00:00:00:00:01', '00:00:00:00:00:02', '00:00:00:00:00:10'}  # u1,u2,server
LINK_BPS = 10e6 / 8          # capacita' dei link (10 Mbps) in byte/s
CONGESTION_UTIL = 0.8        # soglia di utilizzo per il rilevamento da congestione


def make_detector(name):
    """Restituisce (detector, nome per i log)."""
    thr = float(os.environ.get('ML_THRESHOLD', '0.5'))
    if name == 'ml':
        return MLDetector('ml/model.joblib', thr), 'ML (soglia %.2f)' % thr
    if name == 'ensemble':
        return EnsembleDetector([MLDetector('ml/model.joblib', thr),
                                 AdaptiveThresholdDetector()]), 'ML+EWMA (soglia ML %.2f)' % thr
    if name == 'ewma-nohard':
        # configurazione originale: solo EWMA, niente tetto duro, soglie alte
        return AdaptiveThresholdDetector(warmup=5, min_bps=400000, min_pps=1000,
                                         hard_bps=None, hard_pps=None,
                                         min_rel_std=0.0), 'EWMA-nohard'
    return AdaptiveThresholdDetector(), 'EWMA'


class DoSController(simple_switch_stp_13.SimpleSwitch13):
    """Switch L2+STP esteso con monitoring/detection/mitigation del DoS."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)          # inizializza forwarding + STP
        self.datapaths = {}
        # WHITELIST=0 -> nessun host protetto: serve a misurare i falsi positivi del
        # detector (con la whitelist attiva l'isolamento di u1/u2 e' garantito da lei).
        self.whitelist_on = os.environ.get('WHITELIST', '1') != '0'
        ttl = float(os.environ.get('BLOCK_TTL', '60')) or None
        self.blocklist = Blocklist(whitelist=LEGIT if self.whitelist_on else set(), ttl=ttl)
        self.logger.info("Whitelist: %s, BLOCK_TTL: %s", 'ON' if self.whitelist_on else 'OFF',
                         ttl or 'permanente')
        self.detector, self.detector_name = make_detector(os.environ.get('DETECTOR', 'ewma'))
        k, n = (int(x) for x in os.environ.get('CONFIRM', '2/3').split('/'))
        self.confirmer = Confirmer(k, n)
        self.congestion = os.environ.get('CONGESTION', '0') == '1'
        self.logger.info("Detector: %s, conferma %d/%d, congestione: %s",
                         self.detector_name, k, n, 'ON' if self.congestion else 'OFF')
        self.src_features = SourceFeatures()
        self.mitigator = Mitigator(self, self.blocklist)
        # MITIGATE=0 -> rileva e logga ma NON blocca (ablation / raccolta feature attacco)
        self.mitigate = os.environ.get('MITIGATE', '1') != '0'
        # logging feature per costruire il dataset ML; attivo solo con FEATURE_LOG=path
        log_path = os.environ.get('FEATURE_LOG', '')
        self.feature_log = open(log_path, 'a') if log_path else None
        # log eventi DETECT/BLOCK con timestamp epoch (per il tempo di rilevamento);
        # attivo solo con EVENT_LOG=path
        ev_path = os.environ.get('EVENT_LOG', '')
        self.event_log = open(ev_path, 'a') if ev_path else None
        self.monitor = Monitor(self, interval=5, link_bps=LINK_BPS)

    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Override del forwarding L2 del padre: identico, ma installa i flow con match
        anche su eth_src, cosi' le FlowStats portano il MAC sorgente (serve al detector
        per identificare l'attaccante). STP resta gestito da stplib."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst, src = eth.dst, eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        """Tiene aggiornato l'elenco dei datapath attivi (usato dal Monitor)."""
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply(self, ev):
        """Accumula le flow stats; il Monitor chiama on_interval a intervallo completo."""
        more = bool(ev.msg.flags & ev.msg.datapath.ofproto.OFPMPF_REPLY_MORE)
        self.monitor.update_from_reply(ev.msg.datapath.id, ev.msg.body, more=more)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply(self, ev):
        self.monitor.update_from_port_reply(ev.msg.datapath.id, ev.msg.body)

    def on_interval(self, per_src, port_util):
        """Una classificazione per SORGENTE e per intervallo; blocco dopo conferma."""
        util, port = port_util
        talker = None
        if self.congestion and util > CONGESTION_UTIL:
            talker = top_talker(per_src, exclude=self.blocklist.whitelist)
            self.logger.warning("CONGESTION port=%s util=%.0f%% top_talker=%s",
                                port, util * 100, talker)
        for src, m in per_src.items():
            f = self.src_features.update(src, m)
            verdict = self.detector.classify(src, **f)
            reason = self.detector_name
            if src == talker:
                verdict, reason = 'attack', 'Congestion'
            if verdict == 'attack':
                self.logger.warning("DETECT src=%s bps=%.0f pps=%.0f pkt=%.0fB rx=%.0f (%s)",
                                    src, f['bps'], f['pps'], f['pkt_size'],
                                    f.get('rx_pps', -1), reason)
                self._event('DETECT', src, f, reason)
            if (self.confirmer.update(src, verdict) and self.mitigate
                    and self.mitigator.block_mac(src, reason=reason)):
                self._event('BLOCK', src, f, reason)

    def _event(self, kind, src, m, reason):
        if self.event_log:
            self.event_log.write("%.3f,%s,%s,%s,%.0f,%.1f\n" % (
                time.time(), kind, src, reason, m['bps'], m['pps']))
            self.event_log.flush()
