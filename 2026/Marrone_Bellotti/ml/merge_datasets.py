# ml/merge_datasets.py — unisce tutte le raccolte di ml/datasets/ in ml/dataset.csv
#
# Ogni file ml/datasets/<nome>.csv e' una raccolta completa prodotta da
# ml/extract_features.py (una per ogni esecuzione di experiments/gen_dataset.sh).
# Le raccolte non si sovrascrivono: ogni nuova generazione aggiunge un file, e il
# dataset di training e' sempre l'unione di tutte.
#
# I nomi delle run (es. gen_s1#e3) si ripetono tra raccolte diverse: qui ricevono il
# prefisso "<nome del file>_", cosi' la validazione per gruppo di train.py non
# confonde episodi diversi che hanno lo stesso nome.
#
# Uso: python3 ml/merge_datasets.py   (nessun argomento; scrive ml/dataset.csv)
import glob
import os
import sys

import pandas as pd

SRC = 'ml/datasets'
OUT = 'ml/dataset.csv'


def main():
    paths = sorted(glob.glob(os.path.join(SRC, '*.csv')))
    if not paths:
        sys.exit("nessuna raccolta in %s/: generarne una con experiments/gen_dataset.sh" % SRC)
    parts, cols = [], None
    for p in paths:
        df = pd.read_csv(p)
        if cols is None:
            cols = list(df.columns)
        elif list(df.columns) != cols:
            sys.exit("ERRORE: %s ha colonne diverse dalle altre raccolte: %s" % (p, list(df.columns)))
        stem = os.path.splitext(os.path.basename(p))[0]
        df['run'] = stem + '_' + df['run'].astype(str)
        parts.append(df)
        print("  %-20s %5d righe, %3d episodi" % (stem, len(df), df['run'].nunique()))
    out = pd.concat(parts, ignore_index=True)
    out.to_csv(OUT, index=False)
    print("-> %s: %d righe, %d episodi" % (OUT, len(out), out['run'].nunique()))
    print(out.groupby(['family', 'label']).size().to_string())


if __name__ == '__main__':
    main()
