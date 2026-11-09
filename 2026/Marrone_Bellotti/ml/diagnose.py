# ml/diagnose.py — perche' il modello ML va male? Dati pochi o feature insufficienti?
#
# Uso: python3 ml/diagnose.py [--data ml/dataset.csv] [--holdout syn]
#
# Tre controlli, ognuno risponde a una domanda precisa:
#
#  1. SEPARABILITA' (errore di training). Un RandomForest senza limiti di profondita'
#     viene addestrato e valutato SUGLI STESSI dati. Se nemmeno cosi' arriva vicino al
#     100%, esistono righe con feature quasi uguali ed etichette opposte: le feature
#     NON contengono l'informazione, e piu' dati non servono.
#
#  2. CURVA DI APPRENDIMENTO. Si addestra su una frazione crescente dei gruppi di
#     training (10% ... 100%) e si valuta sempre su gruppi mai visti. Se F1 sale ancora
#     all'ultimo punto, piu' dati aiutano. Se e' piatta, il limite e' altrove.
#
#  3. DOVE SBAGLIA. Recall per famiglia di attacco e, per i benigni segnalati, i valori
#     tipici delle loro feature: dice QUALE traffico confonde il modello.
import argparse
import os
import sys

import numpy as np
import pandas as pd
from sklearn.neighbors import NearestNeighbors
from sklearn.metrics import f1_score
from sklearn.model_selection import GroupShuffleSplit

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ml.train import MODELS, FINAL, group_cv, group_splits, prepare  # noqa: E402
from modules.features import FEATURES  # noqa: E402


def separability(df, k=5):
    """Per ogni riga guarda le k righe piu' simili (scala logaritmica, solo di ALTRI
    gruppi, cosi' non conta lo stesso flusso). Ritorna, per classe, la frazione di
    righe i cui vicini sono in maggioranza dell'altra classe: e' la parte dello spazio
    delle feature dove attacco e benigno si sovrappongono."""
    X = np.log1p(df[FEATURES].clip(lower=0).to_numpy())
    X = (X - X.mean(0)) / (X.std(0) + 1e-9)
    y, g = df['label'].to_numpy(), df['group'].to_numpy()
    nn = NearestNeighbors(n_neighbors=min(len(df), 60)).fit(X)
    _, idx = nn.kneighbors(X)
    wrong = np.zeros(len(df), bool)
    for i, row in enumerate(idx):
        other = [j for j in row if g[j] != g[i]][:k]
        if other:
            wrong[i] = (y[other] != y[i]).mean() > 0.5
    return {lbl: wrong[y == lbl].mean() for lbl in (0, 1)}, wrong


def learning_curve(df, fractions=(0.1, 0.25, 0.5, 0.75, 1.0), repeats=10):
    out = {f: [] for f in fractions}
    groups = df['group']
    for r in range(repeats):
        gss = GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=r)
        tr, te = next(gss.split(df, df['label'], groups))
        tr_groups = groups.iloc[tr].unique()
        rng = np.random.default_rng(r)
        rng.shuffle(tr_groups)
        test = df.iloc[te]
        if test['label'].nunique() < 2:
            continue
        for f in fractions:
            keep = tr_groups[:max(2, int(round(f * len(tr_groups))))]
            train = df[groups.isin(keep)]
            if train['label'].nunique() < 2:
                continue
            clf = MODELS[FINAL]().fit(train[FEATURES], train['label'])
            out[f].append((len(train), f1_score(test['label'], clf.predict(test[FEATURES]))))
    return {f: (np.mean([n for n, _ in v]), np.mean([s for _, s in v]), np.std([s for _, s in v]))
            for f, v in out.items() if v}


def where_wrong(df):
    splits, _ = group_splits(df)
    yt, yp = group_cv(df, MODELS[FINAL], FEATURES, splits)
    # group_cv concatena i fold nell'ordine dei test: ricostruisco gli indici
    idx = np.concatenate([te for _, te in splits])
    res = df.iloc[idx].assign(pred=yp)
    fam = res[res.label == 1].groupby('family')['pred'].agg(['mean', 'size'])
    fp = res[(res.label == 0) & (res.pred == 1)]
    tn = res[(res.label == 0) & (res.pred == 0)]
    return fam, fp, tn


def main(data, holdout):
    df = prepare(pd.read_csv(data))
    df = prepare(df[~df['family'].isin(holdout)].copy())
    print("dataset: %d righe, %d gruppi, attacchi %d, benigni %d\n"
          % (len(df), df['group'].nunique(), (df.label == 1).sum(), (df.label == 0).sum()))

    over, wrong = separability(df)
    print("1) SOVRAPPOSIZIONE (5 vicini piu' simili, presi da altri episodi)")
    print("   attacchi circondati da benigni: %.0f%%   benigni circondati da attacchi: %.0f%%"
          % (100 * over[1], 100 * over[0]))
    atk = df[(df.label == 1) & wrong]
    if len(atk):
        print("   attacchi 'nascosti' per famiglia: %s" % atk['family'].value_counts().to_dict())
    print("   -> percentuali basse: le classi sono separate, servono dati piu' vari.")
    print("   -> percentuali alte: attacco e benigno hanno le stesse feature; piu' righe")
    print("      dello stesso tipo non aiutano, serve una feature nuova.\n")

    print("2) CURVA DI APPRENDIMENTO (F1 su gruppi mai visti, media su 10 ripetizioni)")
    for f, (n, mean, std) in learning_curve(df).items():
        print("   %3.0f%% dei gruppi di training (~%4.0f righe): F1 %.2f +/- %.2f" % (100 * f, n, mean, std))
    print("   -> ancora in salita all'ultimo punto: servono piu' dati.")
    print("   -> piatta: piu' dati non cambiano il risultato.\n")

    fam, fp, tn = where_wrong(df)
    print("3) DOVE SBAGLIA (CV per gruppo)")
    print("   recall per famiglia di attacco:")
    for name, r in fam.iterrows():
        print("     %-8s %.2f su %d campioni" % (name, r['mean'], r['size']))
    cols = ['pps', 'bps', 'pkt_size']
    if len(fp):
        print("   benigni segnalati come attacco (%d): mediane %s"
              % (len(fp), fp[cols].median().round(0).to_dict()))
    print("   benigni riconosciuti (%d): mediane %s" % (len(tn), tn[cols].median().round(0).to_dict()))


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', default='ml/dataset.csv')
    ap.add_argument('--holdout', action='append', default=[])
    a = ap.parse_args()
    main(a.data, a.holdout)
