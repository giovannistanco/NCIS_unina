#!/bin/bash
# experiments/demo_screens.sh — esegue tutte le casistiche della demo in un comando.
#
# Uso (dentro il container, da /work):   bash experiments/demo_screens.sh [casistica ...]
# Da PowerShell:                          .\run.ps1 bash experiments/demo_screens.sh
#
# Casistiche (default: tutte, ~13 minuti):
#   1_nomit     soglia adattiva, SENZA mitigazione, flood UDP 25 Mbps
#   2_mit       soglia adattiva, con mitigazione e whitelist, flood UDP 25 Mbps
#   3_nowl      soglia adattiva, con mitigazione SENZA whitelist, flood UDP 25 Mbps
#   4_ml_small  detector ML, senza whitelist, flood UDP a pacchetti piccoli (5 Mbps, 250 B)
#   5_ml_big    detector ML, senza whitelist, flood UDP 25 Mbps a pacchetti grandi
# Nelle casistiche con mitigazione il blocco e' permanente (BLOCK_TTL=0).
# Risultati in experiments/demo/<casistica>/; riepiloghi stampati alla fine.
set -u
cd "$(dirname "$0")/.."
BASE=experiments/demo

declare -A ENVS FLOOD WAIT TITLE
ENVS[1_nomit]="MITIGATE=0";                        FLOOD[1_nomit]=big;    WAIT[1_nomit]=0
ENVS[2_mit]="BLOCK_TTL=0";                         FLOOD[2_mit]=big;      WAIT[2_mit]=1
ENVS[3_nowl]="BLOCK_TTL=0 WHITELIST=0";            FLOOD[3_nowl]=big;     WAIT[3_nowl]=1
ENVS[4_ml_small]="DETECTOR=ml BLOCK_TTL=0 WHITELIST=0"; FLOOD[4_ml_small]=small; WAIT[4_ml_small]=1
ENVS[5_ml_big]="DETECTOR=ml BLOCK_TTL=0 WHITELIST=0";   FLOOD[5_ml_big]=big;     WAIT[5_ml_big]=1
TITLE[1_nomit]="1. Soglia adattiva SENZA mitigazione (MITIGATE=0) - flood UDP 25 Mbps"
TITLE[2_mit]="2. Soglia adattiva CON whitelist (BLOCK_TTL=0) - flood UDP 25 Mbps"
TITLE[3_nowl]="3. Soglia adattiva SENZA whitelist (WHITELIST=0 BLOCK_TTL=0) - flood UDP 25 Mbps"
TITLE[4_ml_small]="4. Detector ML (DETECTOR=ml WHITELIST=0) - flood UDP 5 Mbps, pacchetti 250 B"
TITLE[5_ml_big]="5. Detector ML (DETECTOR=ml WHITELIST=0) - flood UDP 25 Mbps, pacchetti grandi"

CASES=("$@")
[ ${#CASES[@]} -eq 0 ] && CASES=(1_nomit 2_mit 3_nowl 4_ml_small 5_ml_big)

for c in "${CASES[@]}"; do
    OUT=$BASE/$c
    mkdir -p "$OUT"; rm -f "$OUT"/*
    echo "=== [$c] controller: ${ENVS[$c]}"
    pkill -f "ryu-manager controller.py" 2>/dev/null; mn -c >/dev/null 2>&1; pkill -f iperf 2>/dev/null
    env PYTHONPATH=. ${ENVS[$c]} EVENT_LOG="$OUT/eventi.csv" \
        ryu-manager controller.py > "$OUT/controller_completo.log" 2>&1 &
    ctrl=$!
    sleep 4
    python3 experiments/demo_screens.py "$OUT" "${FLOOD[$c]}" "${WAIT[$c]}" > "$OUT/mininet.log" 2>&1
    kill $ctrl 2>/dev/null; wait $ctrl 2>/dev/null
    mn -c >/dev/null 2>&1
    grep -E "Whitelist|Detector|DETECT|^BLOCK " "$OUT/controller_completo.log" > "$OUT/controller.txt"
done

clear 2>/dev/null
for c in "${CASES[@]}"; do
    python3 experiments/demo_summary.py "$BASE/$c" "${TITLE[$c]}"
done
