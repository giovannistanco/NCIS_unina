# ml/train.py — addestra il MLDetector e lo confronta con le baseline
#
# Uso: python3 ml/train.py [--data ml/dataset.csv] [--holdout FAMIGLIA ...] [test_extra.csv ...]
#   --holdout F    : la famiglia di attacco F (es. syn) e' TOLTA dal training e usata
#                    solo come test: misura la generalizzazione ad attacchi mai visti.
#   test_extra.csv : altri dataset (da extract_features.py) valutati col modello finale.
#
# Valutazione: le righe sono campioni consecutivi delle stesse sorgenti. Uno split
# casuale mette la stessa sorgente in train e in test e gonfia il risultato. Il gruppo
# e' (run, MAC sorgente): con almeno 5 gruppi per classe si usa StratifiedGroupKFold a
# 5 fold, altrimenti leave-one-pair-out (un host benigno + uno attaccante per fold).
#
# Metriche sull'attacco: precision, recall, F1 e false positive rate (FPR = benigni
# segnalati come attacco / benigni). L'accuracy da sola e' ingannevole con classi
# sbilanciate.
#
# Valutazione per host: le metriche per riga non dicono chi viene bloccato. Per ogni
# (episodio, sorgente) si applica ai verdetti la conferma 2/3 del controller: un
# attaccante e' bloccato se la conferma scatta durante l'attacco, un host onesto
# (nessun intervallo di attacco nell'episodio) e' bloccato per errore se scatta in
# qualunque momento.
#
# lowrate (TEST_ONLY) non entra mai nel training: a 50-200 pps non fa danni ed e'
# indistinguibile dal benigno, etichettarlo come attacco confonde il modello. Viene
# valutato solo come test, come le famiglie passate con --holdout.
#
# Output: ml/model.joblib, ml/confusion_matrix.png, ml/tree_rules.txt, ml/results.md
import argparse
import itertools
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.tree import DecisionTreeClassifier, export_text

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from modules.detector import ACTIVE_FLOOR, AdaptiveThresholdDetector, Confirmer  # noqa: E402
from modules.features import FEATURES  # noqa: E402

TEST_ONLY = ['lowrate']

# `dur` e' esclusa: i flussi di attacco appena installati hanno dur=0 e il modello la
# userebbe come scorciatoia (vedi ablation).
MODELS = {
    'RandomForest (max_depth=4)': lambda: RandomForestClassifier(
        n_estimators=100, max_depth=4, class_weight='balanced', random_state=42),
    'DecisionTree (max_depth=3)': lambda: DecisionTreeClassifier(
        max_depth=3, class_weight='balanced', random_state=42),
}
FINAL = 'RandomForest (max_depth=4)'


def prepare(df):
    if 'run' not in df.columns:
        df['run'] = 'run0'
    if 'family' not in df.columns:
        df['family'] = np.where(df['label'] == 1, 'unknown', 'benign')
    if 'pkt_size' not in df.columns:
        df['pkt_size'] = (df['bps'] / df['pps']).where(df['pps'] > 0, 0.0)
    if 'dpps' not in df.columns:
        df['dpps'] = 0.0
    if 'poll' not in df.columns:
        df['poll'] = np.arange(len(df))
    df['group'] = df['run'].astype(str) + '|' + df['eth_src']
    return df.reset_index(drop=True)


def metrics(y, p):
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {'precision': prec, 'recall': rec, 'F1': f1, 'FPR': fpr}


def group_splits(df):
    g, ben = df['group'], df.loc[df.label == 0, 'group'].unique()
    atk = df.loc[df.label == 1, 'group'].unique()
    if min(len(ben), len(atk)) >= 5:
        sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
        return list(sgkf.split(df, df['label'], g)), 'StratifiedGroupKFold 5 fold'
    splits = []
    for b, a in itertools.product(sorted(ben), sorted(atk)):
        test = g.isin([b, a]).to_numpy()
        if df.loc[~test, 'label'].nunique() == 2:
            splits.append((np.where(~test)[0], np.where(test)[0]))
    return splits, 'leave-one-pair-out %d fold (campioni ripetuti tra fold)' % len(splits)


def group_cv(df, make, features, splits):
    yt, yp = [], []
    for tr, te in splits:
        clf = make().fit(df.iloc[tr][features], df.iloc[tr]['label'])
        yt.extend(df.iloc[te]['label']); yp.extend(clf.predict(df.iloc[te][features]))
    return np.array(yt), np.array(yp)


def cv_predict(df, make, features, splits):
    """Come group_cv, ma allineata alle righe di df: ogni riga ha la predizione del
    fold in cui e' di test (serve alla valutazione per host)."""
    pred = np.zeros(len(df), dtype=int)
    for tr, te in splits:
        clf = make().fit(df.iloc[tr][features], df.iloc[tr]['label'])
        pred[te] = clf.predict(df.iloc[te][features])
    return pred


def per_host(df, pred, k=2, n=3):
    """Conferma k/n per (episodio, sorgente) in ordine di tempo, come il controller.
    Ritorna (attaccanti bloccati, attaccanti), (onesti bloccati, onesti)."""
    caught, wrong = [], []
    d = df.assign(pred=pred).sort_values('poll')
    for _, g in d.groupby('group'):
        c = Confirmer(k, n)
        fired = np.array([c.update('s', 'attack' if p else 'benign') for p in g['pred']])
        attack = (g['label'] == 1).to_numpy()
        if attack.any():
            caught.append(fired[attack].any())
        else:
            wrong.append(fired.any())
    return (sum(caught), len(caught)), (sum(wrong), len(wrong))


def pct(hit_total):
    hit, total = hit_total
    return '%.0f%% (%d/%d)' % (100 * hit / total, hit, total) if total else '-'


def host_table(rows):
    lines = ['| Metodo | Attaccanti bloccati | Host onesti bloccati |', '|---|---|---|']
    lines += ['| %s | %s | %s |' % (name, pct(c), pct(w)) for name, (c, w) in rows]
    return '\n'.join(lines)


def replay_ewma(df, **kw):
    """Applica il detector adattivo alla sequenza temporale di ogni (run, sorgente),
    come farebbe il controller: stessa baseline per tutti i dati, nessun training."""
    pred = pd.Series(0, index=df.index)
    for _, g in df.sort_values('poll').groupby('group'):
        d = AdaptiveThresholdDetector(**kw)
        for i, r in g.iterrows():
            pred[i] = int(d.classify('s', bps=r['bps'], pps=r['pps']) == 'attack')
    return pred.to_numpy()


def static_threshold(df):
    d = AdaptiveThresholdDetector()
    return ((df['bps'] > d.hard['bps']) | (df['pps'] > d.hard['pps'])).astype(int).to_numpy()


def save_confusion(cm, title, path):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(3.4, 3))
    ax.imshow(cm, cmap='Blues')
    for (i, j), v in np.ndenumerate(cm):
        ax.text(j, i, str(v), ha='center', va='center',
                color='white' if v > cm.max() / 2 else 'black')
    ax.set_xticks([0, 1], ['benigno', 'attacco']); ax.set_yticks([0, 1], ['benigno', 'attacco'])
    ax.set_xlabel('predetto'); ax.set_ylabel('reale'); ax.set_title(title, fontsize=9)
    fig.tight_layout(); fig.savefig(path, dpi=150); plt.close(fig)
    print('salvato', path)


def table(rows):
    lines = ['| Metodo | Precision | Recall | F1 | FPR |', '|---|---|---|---|---|']
    for name, m in rows:
        lines.append('| %s | %.2f | %.2f | %.2f | %.2f |'
                     % (name, m['precision'], m['recall'], m['F1'], m['FPR']))
    return '\n'.join(lines)


def main(data, holdout, extra_tests):
    holdout = list(dict.fromkeys(TEST_ONLY + holdout))
    full = prepare(pd.read_csv(data))
    hold = full[full['family'].isin(holdout)]
    df = prepare(full[~full['family'].isin(holdout)].copy())
    report = []
    print("righe: %d (benigne %d, attacco %d), gruppi (run|host): %d, famiglie: %s"
          % (len(df), (df.label == 0).sum(), (df.label == 1).sum(), df['group'].nunique(),
             ', '.join(sorted(df.loc[df.label == 1, 'family'].unique()))))
    for lbl, name in [(0, 'benigno'), (1, 'attacco')]:
        d = df[df.label == lbl]
        print("  %s: pps mediana %.0f [%.0f-%.0f], pkt_size mediana %.0f B [%.0f-%.0f]"
              % (name, d.pps.median(), d.pps.min(), d.pps.max(),
                 d.pkt_size.median(), d.pkt_size.min(), d.pkt_size.max()))

    splits, how = group_splits(df)
    print("\nCV per gruppo: %s" % how)
    if not splits:
        sys.exit("ERRORE: servono almeno 2 gruppi (episodio, host) per classe per la CV: "
                 "generare piu' episodi (experiments/gen_dataset.sh)")
    rows = []
    for name, make in MODELS.items():
        yt, yp = group_cv(df, make, FEATURES, splits)
        rows.append((name, metrics(yt, yp)))
        if name == FINAL:
            cm = confusion_matrix(yt, yp, labels=[0, 1])
            save_confusion(cm, 'CV per gruppo (%s)' % name.split()[0], 'ml/confusion_matrix.png')
    no_ps = [f for f in FEATURES if f != 'pkt_size']
    yt, yp = group_cv(df, MODELS[FINAL], no_ps, splits)
    rows.append(('RandomForest senza pkt_size', metrics(yt, yp)))
    yt, yp = group_cv(df, MODELS[FINAL], ['dur'], splits)
    rows.append(('ablation: solo dur (scorciatoia)', metrics(yt, yp)))
    # baseline senza training: valutate su tutte le righe
    y = df['label'].to_numpy()
    preds = {
        'RandomForest (max_depth=4)': cv_predict(df, MODELS[FINAL], FEATURES, splits),
        'Soglia statica (tetto duro)': static_threshold(df),
        'EWMA senza tetto (originale)': replay_ewma(
            df, warmup=5, min_bps=400000, min_pps=1000, hard_bps=None, hard_pps=None,
            min_rel_std=0.0),
        'EWMA + tetto duro': replay_ewma(df),
    }
    for name in list(preds)[1:]:
        rows.append((name, metrics(y, preds[name])))
    t = table(rows)
    print(t)
    report += ['## CV per gruppo (%s)' % how, '', t, '']
    ht = host_table([(name, per_host(df, p)) for name, p in preds.items()])
    print("\nPer host (episodio, sorgente), conferma 2/3:\n" + ht)
    report += ['## Per host (episodio, sorgente), conferma 2/3', '', ht, '']

    clf = MODELS[FINAL]().fit(df[FEATURES], df['label'])
    imp = dict(zip(FEATURES, clf.feature_importances_.round(3)))
    print("feature importances:", imp)
    report += ['Feature importances (RF finale): %s' % imp, '']
    tree = MODELS['DecisionTree (max_depth=3)']().fit(df[FEATURES], df['label'])
    open('ml/tree_rules.txt', 'w').write(export_text(tree, feature_names=FEATURES))
    print('salvato ml/tree_rules.txt (regole dell\'albero, da spiegare a voce)')
    joblib.dump({'model': clf, 'features': FEATURES, 'active_floor': ACTIVE_FLOOR},
                'ml/model.joblib')
    print('salvato ml/model.joblib')

    tests = [('famiglia tenuta fuori: %s' % f, prepare(hold[hold['family'] == f].copy()))
             for f in holdout if (hold['family'] == f).any()]
    tests += [(p, prepare(pd.read_csv(p))) for p in extra_tests]
    for name, t in tests:
        y = t['label'].to_numpy()
        rec = lambda p: (p[y == 1] == 1).mean() if (y == 1).any() else float('nan')  # noqa: E731
        res = [('RandomForest', clf.predict(t[FEATURES])),
               ('Soglia statica', static_threshold(t)),
               ('EWMA + tetto duro', replay_ewma(t))]
        line = '; '.join('%s recall %.2f, attaccanti bloccati %s'
                         % (n, rec(p), pct(per_host(t, p)[0])) for n, p in res)
        print("\n[test] %s: %d righe di attacco -> %s" % (name, (y == 1).sum(), line))
        report += ['## Test: %s' % name, '', '%d campioni di attacco. %s' % ((y == 1).sum(), line), '']

    open('ml/results.md', 'w').write('\n'.join(report))
    print('salvato ml/results.md')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--holdout', action='append', default=[])
    ap.add_argument('--data', default='ml/dataset.csv')
    ap.add_argument('extra', nargs='*')
    a = ap.parse_args()
    main(a.data, a.holdout, a.extra)
