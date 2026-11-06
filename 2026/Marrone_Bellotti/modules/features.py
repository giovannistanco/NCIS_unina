# modules/features.py — feature per SORGENTE, condivise tra controller (runtime) e
# ml/extract_features.py (offline): stessa funzione => stesse feature in training e
# in esercizio.
#
# Una sorgente (MAC) ha in genere piu' flussi (uno per destinatario) ed e' vista da
# piu' switch lungo il percorso. Per ogni intervallo di polling:
#   1. per ogni switch si SOMMANO i flussi della sorgente (tutto il suo traffico li');
#   2. tra gli switch si prende il MASSIMO, che coincide con lo switch di ingresso
#      (a valle il traffico puo' solo diminuire).
# Cosi' ogni sorgente produce UNA osservazione per intervallo: niente baseline
# duplicate per switch, niente ripartenza da zero a ogni nuovo destinatario.

FEATURES = ['pps', 'bps', 'pkt_size', 'dpps']


def aggregate_by_source(rows):
    """rows: iterabile di (dpid, eth_src, pps, bps, dur) di UN intervallo.
    Ritorna {eth_src: {'pps', 'bps', 'dur'}}."""
    per_sw = {}
    for dpid, src, pps, bps, dur in rows:
        if src is None:
            continue
        cur = per_sw.setdefault((dpid, src), {'pps': 0.0, 'bps': 0.0, 'dur': 0})
        cur['pps'] += pps
        cur['bps'] += bps
        cur['dur'] = max(cur['dur'], dur)
    out = {}
    for (_, src), m in per_sw.items():
        best = out.get(src)
        if best is None or m['bps'] > best['bps']:
            out[src] = dict(m)
    return out


def aggregate_by_dest(rows):
    """rows: iterabile di (dpid, eth_dst, pps) di UN intervallo.
    Ritorna {eth_dst: pps}: i pacchetti/s che l'host RICEVE (somma per switch, massimo
    tra gli switch, come per le sorgenti). Per un TCP legittimo sono gli ACK di
    ritorno; un flood UDP verso un server non riceve quasi niente."""
    per_sw = {}
    for dpid, dst, pps in rows:
        if dst is None:
            continue
        per_sw[(dpid, dst)] = per_sw.get((dpid, dst), 0.0) + pps
    out = {}
    for (_, dst), pps in per_sw.items():
        out[dst] = max(out.get(dst, 0.0), pps)
    return out


def derive(pps, bps, prev_pps):
    """Feature derivate: dimensione media del pacchetto e variazione di pps rispetto
    all'intervallo precedente della stessa sorgente (0 se non c'e' storia)."""
    return {'pkt_size': bps / pps if pps > 0 else 0.0,
            'dpps': pps - prev_pps if prev_pps is not None else 0.0}


class SourceFeatures:
    """Stato per sorgente tra un intervallo e l'altro (serve per dpps)."""

    def __init__(self):
        self.prev_pps = {}

    def update(self, src, m):
        f = {'pps': m['pps'], 'bps': m['bps'], 'dur': m['dur']}
        if 'rx_pps' in m:          # solo a runtime (il FEATURE_LOG non ha eth_dst)
            f['rx_pps'] = m['rx_pps']
        f.update(derive(m['pps'], m['bps'], self.prev_pps.get(src)))
        self.prev_pps[src] = m['pps']
        return f
