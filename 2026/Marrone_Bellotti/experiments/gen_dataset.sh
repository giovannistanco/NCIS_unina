#!/bin/bash
# experiments/gen_dataset.sh — genera il dataset ML e addestra il modello.
#
# Uso (dentro il container, da /work):
#   bash experiments/gen_dataset.sh [sessioni=2] [episodi_per_famiglia=5]
#
# Ogni sessione: controller con MITIGATE=0 e FEATURE_LOG, poi experiments/gen_dataset.py
# con un seed diverso (4 famiglie x N episodi + ~25% episodi solo benigni, 65 s
# ciascuno: con i default ~27 min a sessione). Con 2 sessioni e 5 episodi si hanno 10
# episodi per famiglia; per 20 usare  bash experiments/gen_dataset.sh 4 5.
#
# Alla fine la raccolta viene salvata come NUOVO file in ml/datasets/ (nome dato da
# SET, default set_<data>_<ora>): le raccolte precedenti non vengono toccate.
# ml/merge_datasets.py le unisce tutte in ml/dataset.csv e si addestra con la famiglia
# HOLDOUT (default syn) tenuta fuori dal training come test di generalizzazione:
#   HOLDOUT=icmp bash experiments/gen_dataset.sh
#   SET=set3 bash experiments/gen_dataset.sh
# Log grezzi in ml/raw/ (non versionati); risultati in ml/results.md.
set -u
cd "$(dirname "$0")/.."
SESSIONS=${1:-2}
PER=${2:-5}
HOLDOUT=${HOLDOUT:-syn}
SET=${SET:-set_$(date +%Y%m%d_%H%M)}
mkdir -p ml/raw ml/datasets
if [ -e "ml/datasets/$SET.csv" ]; then
    echo "ERRORE: ml/datasets/$SET.csv esiste gia': scegliere un altro SET"; exit 1
fi

for s in $(seq 1 "$SESSIONS"); do
    tag=ml/raw/gen_s$s
    rm -f "$tag.csv" "$tag.meta.jsonl"
    echo "=== sessione $s/$SESSIONS (seed $s)"
    pkill -f "ryu-manager controller.py" 2>/dev/null; mn -c >/dev/null 2>&1
    env PYTHONPATH=. MITIGATE=0 FEATURE_LOG="$tag.csv" \
        ryu-manager controller.py > "ml/raw/ctrl_s$s.log" 2>&1 &
    ctrl=$!
    sleep 4
    python3 experiments/gen_dataset.py "$tag.meta.jsonl" --per-family "$PER" --seed "$s"
    kill $ctrl 2>/dev/null; wait $ctrl 2>/dev/null
    mn -c >/dev/null 2>&1
done

python3 ml/extract_features.py -o "ml/datasets/$SET.csv" ml/raw/gen_s*.csv
python3 ml/merge_datasets.py
python3 ml/train.py --holdout "$HOLDOUT" | tee experiments/ml_train.log
