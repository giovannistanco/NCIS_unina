# modules/monitor.py
# ryu.lib.hub lo importo dentro i metodi che lo usano (spawn/sleep), non qui:
# così per_interval_rate resta testabile senza avere Ryu installato in locale.
import time

from modules.features import aggregate_by_dest, aggregate_by_source
from modules.mitigator import DROP_PRIORITY


def per_interval_rate(prev, curr, interval):
    """Converte contatori cumulativi OpenFlow in rate per-intervallo (unità/s)."""
    if prev is None or interval <= 0:
        return 0.0
    delta = curr - prev
    if delta < 0:            # reset del contatore
        return 0.0
    return delta / interval


class Monitor:
    """Poll periodico di flow stats e port stats.

    Ogni ciclo di polling e' un intervallo numerato (`poll`). Le reply dei vari switch
    arrivano separate: il Monitor le accumula e, quando hanno risposto tutti gli switch
    interrogati (o al ciclo successivo, se uno non risponde), chiude l'intervallo e
    chiama app.on_interval(per_src, port_util) con UNA osservazione per sorgente
    (vedi modules/features.py), compresi i pacchetti/s che la sorgente riceve
    (`rx_pps`), e l'utilizzo massimo dei link.

    Formato FEATURE_LOG (una riga per flusso e switch, deduplicata offline):
        dpid,eth_src,pps,bps,dur,pkts,bytes,ts,poll
    """

    def __init__(self, app, interval=5, start=True, link_bps=10e6 / 8):
        self.app = app                 # riferimento al RyuApp (per logger, datapaths)
        self.interval = interval
        self.link_bps = link_bps       # capacita' dei link in byte/s (per l'utilizzo)
        self.prev = {}                 # {(dpid,in_port,eth_src,eth_dst): (pkts,bytes)}
        self.flow_metrics = {}         # {(dpid,...): {'pps':..,'bps':..,'dur':..}}
        self.prev_port = {}            # {(dpid,port): tx_bytes}
        self.port_bps = {}             # {(dpid,port): tx byte/s nell'ultimo intervallo}
        self.poll = 0
        self.pending = set()           # dpid che non hanno ancora risposto in questo poll
        self.rows = []                 # (dpid, src, pps, bps, dur) dell'intervallo corrente
        self.rx_rows = []              # (dpid, dst, pps): traffico ricevuto da ogni host
        self.thread = None
        if start:                      # start=False nei test: niente thread Ryu
            from ryu.lib import hub
            self.thread = hub.spawn(self._loop)

    def _loop(self):
        from ryu.lib import hub
        while True:
            if self.rows:              # uno switch non ha risposto: chiudo comunque
                self._flush()
            self.poll += 1
            dps = list(self.app.datapaths.values())
            self.pending = {dp.id for dp in dps}
            for dp in dps:
                self._request(dp)
            hub.sleep(self.interval)

    def _request(self, dp):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        dp.send_msg(parser.OFPFlowStatsRequest(dp))
        dp.send_msg(parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY))

    def update_from_reply(self, dpid, body, more=False):
        """Chiamata dall'handler FlowStatsReply del RyuApp (`more` = la reply continua
        in un altro messaggio multipart).

        Ritorna SOLO le metriche dei flussi contenuti in questa risposta (cioe' di
        questo switch, in questo intervallo): restituire tutto self.flow_metrics
        farebbe riclassificare a ogni reply anche i flussi degli altri switch, con
        valori vecchi, aggiornando l'EWMA piu' volte con lo stesso campione."""
        current = {}
        now = time.time()
        for stat in body:
            if stat.priority == 0:     # salta la regola di default (table-miss)
                continue
            # salta le regole di drop del Mitigator: contano il traffico SCARTATO, e un
            # attaccante bloccato sembrerebbe ancora attivo (falserebbe anche top_talker)
            if stat.priority == DROP_PRIORITY:
                continue
            m = stat.match
            src = m.get('eth_src')
            key = (dpid, m.get('in_port'), src, m.get('eth_dst'))
            p_pkts, p_bytes = self.prev.get(key, (None, None))
            met = {
                'pps': per_interval_rate(p_pkts, stat.packet_count, self.interval),
                'bps': per_interval_rate(p_bytes, stat.byte_count, self.interval),
                'dur': stat.duration_sec,
                'eth_src': src,
            }
            self.flow_metrics[key] = met
            self.rows.append((dpid, src, met['pps'], met['bps'], met['dur']))
            self.rx_rows.append((dpid, m.get('eth_dst'), met['pps']))
            # logging opzionale delle feature per il dataset ML
            if getattr(self.app, 'feature_log', None):
                self.app.feature_log.write(
                    f"{dpid},{src},{met['pps']:.2f},{met['bps']:.2f},{stat.duration_sec},"
                    f"{stat.packet_count},{stat.byte_count},{now:.3f},{self.poll}\n")
                self.app.feature_log.flush()
            self.prev[key] = (stat.packet_count, stat.byte_count)
            current[key] = met
        if not more:
            self.pending.discard(dpid)
            if not self.pending:
                self._flush()
        return current

    def update_from_port_reply(self, dpid, body):
        """Rate di trasmissione per porta (byte/s). Le port stats possono arrivare dopo
        le flow stats: in quel caso l'intervallo usa l'utilizzo del poll precedente."""
        for stat in body:
            key = (dpid, stat.port_no)
            self.port_bps[key] = per_interval_rate(self.prev_port.get(key), stat.tx_bytes,
                                                   self.interval)
            self.prev_port[key] = stat.tx_bytes

    def port_util(self):
        """Utilizzo massimo (0..1+) tra tutti i link, e la porta corrispondente."""
        if not self.port_bps:
            return 0.0, None
        key = max(self.port_bps, key=self.port_bps.get)
        return self.port_bps[key] / self.link_bps, key

    def _flush(self):
        per_src = aggregate_by_source(self.rows)
        rx = aggregate_by_dest(self.rx_rows)
        for src, m in per_src.items():
            m['rx_pps'] = rx.get(src, 0.0)
        self.rows, self.rx_rows, self.pending = [], [], set()
        handler = getattr(self.app, 'on_interval', None)
        if handler:
            handler(per_src, self.port_util())
