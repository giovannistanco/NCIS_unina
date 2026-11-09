# ml/extract_features.py — log grezzi del monitor -> dataset etichettato per sorgente
#
# Input: i FEATURE_LOG del controller, una riga per flusso e switch:
#   dpid,eth_src,pps,bps,dur,pkts,bytes,ts,poll
# e, accanto a ciascuno, <nome>.meta.jsonl scritto da experiments/gen_dataset.py: un
# episodio per riga, con finestra temporale, attaccanti e finestra dell'attacco.
#
# Elaborazione:
#  1. deduplica: per ogni intervallo (poll) UNA riga per sorgente, con la stessa
#     aggregazione del controller (modules/features.py: somma dei flussi per switch,
#     massimo tra switch = switch di ingresso);
#  2. feature derivate pkt_size = bps/pps e dpps (variazione rispetto al poll prima);
#  3. etichetta PER FINESTRA TEMPORALE: attacco solo se la sorgente e' un attaccante
#     dell'episodio E l'intervallo [ts-5s, ts] cade per almeno meta' nella finestra
#     dell'attacco. Il traffico dell'attaccante prima/dopo il flood e' benigno; gli
#     intervalli a cavallo (meno di meta') sono scartati perche' ambigui;
#  4. scarta i campioni inattivi (bps <= ACTIVE_FLOOR), come fa il MLDetector.
# Ogni episodio diventa una `run` (gruppo per la CV in train.py).
#
# Senza .meta.jsonl (vecchi log, formato a 7 colonne) si ricade nell'etichetta per
# MAC, con un avviso: e' l'etichettatura imprecisa da evitare.
#
# Uso: python3 ml/extract_features.py [-o out.csv] <feat1.csv> [feat2.csv ...]
import json
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from modules.detector import ACTIVE_FLOOR  # noqa: E402  (stesso filtro del MLDetector)
from modules.features import SourceFeatures, aggregate_by_source  # noqa: E402

ATTACKER_MACS = {'00:00:00:00:00:f1', '00:00:00:00:00:f2'}
# hsrv e' escluso: durante un flood ICMP/SYN le sue risposte (echo reply, RST) sono a
# loro volta un "flood" etichettato benigno, rumore che confonderebbe il modello. Il
# server e' in whitelist; il caso del riflettore e' discusso come limite.
EXCLUDE_MACS = {'00:00:00:00:00:10'}
COLS = ['dpid', 'eth_src', 'pps', 'bps', 'dur', 'pkts', 'bytes', 'ts', 'poll']
INTERVAL = 5.0


def per_source(raw):
    """Una riga per (poll, sorgente) con feature aggregate e derivate."""
    raw = raw[raw['eth_src'].notna() & (raw['eth_src'] != 'None')
              & ~raw['eth_src'].isin(EXCLUDE_MACS)]
    sf, out = SourceFeatures(), []
    for poll, g in raw.groupby('poll', sort=True):
        rows = zip(g['dpid'], g['eth_src'], g['pps'], g['bps'], g['dur'])
        for src, m in aggregate_by_source(rows).items():
            f = sf.update(src, m)
            out.append(dict(f, poll=poll, ts=g['ts'].max(), eth_src=src))
    return pd.DataFrame(out)


def overlap(a0, a1, b0, b1):
    return max(0.0, min(a1, b1) - max(a0, b0))


def label_with_meta(df, episodes, stem):
    rows = []
    for _, r in df.iterrows():
        for ep in episodes:
            if not (ep['t0'] <= r['ts'] <= ep['t1']):
                continue
            label, family = 0, 'benign'
            if r['eth_src'] in ep['attackers']:
                frac = overlap(r['ts'] - INTERVAL, r['ts'],
                               ep['atk_start'], ep['atk_end']) / INTERVAL
                if frac >= 0.5:
                    label, family = 1, ep['family']
                elif frac > 0:
                    break                      # intervallo a cavallo: ambiguo, scartato
            rows.append(dict(r, run='%s#e%d' % (stem, ep['episode']),
                             label=label, family=family))
            break
    return pd.DataFrame(rows)


def load(path):
    stem = os.path.splitext(os.path.basename(path))[0]
    raw = pd.read_csv(path, names=COLS)
    meta = os.path.splitext(path)[0] + '.meta.jsonl'
    if raw['poll'].isna().all():
        # vecchio formato (senza ts/poll): niente deduplica possibile
        print("ATTENZIONE: %s senza ts/poll: niente deduplica, etichetta per MAC" % path)
        df = raw[raw['eth_src'].notna() & (raw['eth_src'] != 'None')].copy()
        df['pkt_size'] = (df['bps'] / df['pps']).where(df['pps'] > 0, 0.0)
        df['dpps'] = 0.0
        df['label'] = df['eth_src'].isin(ATTACKER_MACS).astype(int)
        df['family'] = df['label'].map({0: 'benign', 1: 'unknown'})
        df['run'] = stem
    else:
        df = per_source(raw)
        if os.path.exists(meta):
            episodes = [json.loads(line) for line in open(meta) if line.strip()]
            df = label_with_meta(df, episodes, stem)
        else:
            print("ATTENZIONE: %s non trovato: etichetta per MAC (imprecisa)" % meta)
            df['label'] = df['eth_src'].isin(ATTACKER_MACS).astype(int)
            df['family'] = df['label'].map({0: 'benign', 1: 'unknown'})
            df['run'] = stem
    if df.empty:
        return df
    return df[df['bps'] > ACTIVE_FLOOR]          # solo flussi attivi (come a runtime)


if __name__ == '__main__':
    args = sys.argv[1:]
    out = 'ml/dataset.csv'
    if args[:1] == ['-o']:
        out, args = args[1], args[2:]
    if not args:
        print("uso: python3 ml/extract_features.py [-o out.csv] <feat1.csv> [feat2.csv ...]")
        sys.exit(2)
    df = pd.concat([load(p) for p in args], ignore_index=True)
    cols = ['run', 'family', 'eth_src', 'poll', 'ts', 'pps', 'bps', 'dur',
            'pkt_size', 'dpps', 'label']
    df = df[[c for c in cols if c in df.columns]]
    df.to_csv(out, index=False)
    print("righe totali:", len(df), "->", out, "| episodi (run):", df['run'].nunique())
    print(df.groupby(['family', 'label']).size())
