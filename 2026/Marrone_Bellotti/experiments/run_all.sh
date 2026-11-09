#!/bin/bash
# experiments/run_all.sh — esegue gli esperimenti senza gestire due terminali:
# per ognuno avvia il controller (con le variabili d'ambiente giuste) in background,
# lancia lo scenario Mininet, poi ferma controller e pulisce Mininet.
#
# Uso (dentro il container, da /work):
#   experiments/run_all.sh <esperimento> [...]
#
# Esperimenti:
#   topo     reachability + verifica del percorso STP (topology.py --test)
#   nomit    soglia adattiva, senza mitigazione
#   mit      soglia adattiva, con mitigazione
#   nowl     con mitigazione ma SENZA whitelist (falsi positivi)
#   both     a1+a2 insieme, senza whitelist (attacco distribuito)
#   ml-data  genera il dataset (experiments/gen_dataset.sh, 2 sessioni, ~55 min) + training
#   ml-demo  demo end-to-end del MLDetector (a1+a2+u1+u2)
#   cold     flood "a freddo" (a1 al massimo da t=0) con tre detector:
#            EWMA originale (senza tetto), ML, EWMA con tetto duro -> ev_cold_*.csv
#   syn      flood verso un servizio che risponde: SYN piccoli, SYN grandi, SYN grandi a freddo
#   analyze  tempi di detection di tutti i run (non richiede Mininet)
#   all      tutto quanto sopra, in ordine (~1 h 30 min)
#
# Log del controller: experiments/ctrl_<esperimento>.log
set -u
cd "$(dirname "$0")/.."

run() {                   # run <nome> "<VAR=val ...>" <comando scenario...>
    local name=$1 envs=$2; shift 2
    echo "=== [$name] controller: ${envs:-default}"
    pkill -f "ryu-manager controller.py" 2>/dev/null; mn -c >/dev/null 2>&1
    # prima di avviare il controller: lui apre EVENT_LOG all'avvio, cancellarlo dopo
    # lo farebbe scrivere su un file non piu' visibile
    rm -f "experiments/ev_$name.csv"
    env PYTHONPATH=. $envs ryu-manager controller.py > "experiments/ctrl_$name.log" 2>&1 &
    local ctrl=$!
    sleep 4
    "$@"
    local rc=$?
    kill $ctrl 2>/dev/null; wait $ctrl 2>/dev/null
    mn -c >/dev/null 2>&1
    echo "=== [$name] finito (exit $rc)"
    return $rc
}

scn() {                   # scn <nome> [--both] : scenario soglia adattiva
    local name=$1; shift
    rm -f experiments/u1_tcp_$name.log*
    python3 experiments/scenario.py "experiments/u1_tcp_$name.log" "$@"
}

analyze() {
    for n in mit nowl both cold_nohard cold_ml cold_ewma; do
        [ -f experiments/ev_$n.csv ] || { echo "--- $n: nessun EVENT_LOG"; continue; }
        echo "--- $n"
        python3 experiments/detection_time.py experiments/ev_$n.csv \
            experiments/u1_tcp_$n.log.flood_start*
    done
}

for exp in "$@"; do
    case $exp in
    topo)    run topo "" python3 topology.py --test ;;
    nomit)   run nomit "MITIGATE=0 EVENT_LOG=experiments/ev_nomit.csv" scn nomit ;;
    mit)     run mit "EVENT_LOG=experiments/ev_mit.csv" scn mit ;;
    nowl)    run nowl "WHITELIST=0 EVENT_LOG=experiments/ev_nowl.csv" scn nowl ;;
    both)    run both "WHITELIST=0 EVENT_LOG=experiments/ev_both.csv" scn both --both ;;
    ml-data) bash experiments/gen_dataset.sh ;;
    ml-demo)
        rm -f experiments/ev_ml.csv
        run ml-demo "DETECTOR=ml EVENT_LOG=experiments/ev_ml.csv" \
            python3 experiments/scenario_ml.py both 60
        echo "--- eventi MLDetector:"; cat experiments/ev_ml.csv ;;
    cold)
        run cold_nohard "DETECTOR=ewma-nohard EVENT_LOG=experiments/ev_cold_nohard.csv" \
            scn cold_nohard --cold
        run cold_ml "DETECTOR=ml EVENT_LOG=experiments/ev_cold_ml.csv" scn cold_ml --cold
        run cold_ewma "EVENT_LOG=experiments/ev_cold_ewma.csv" scn cold_ewma --cold ;;
    syn)     # flood verso un servizio che risponde (SYN alla porta TCP di hsrv), senza whitelist
        run synW "WHITELIST=0 EVENT_LOG=experiments/ev_synW.csv" scn synW --syn
        run sbW "WHITELIST=0 EVENT_LOG=experiments/ev_sbW.csv" scn sbW --synbig
        run sbC "WHITELIST=0 EVENT_LOG=experiments/ev_sbC.csv" scn sbC --synbig --cold ;;
    analyze) analyze ;;
    all)     bash "$0" topo nomit mit nowl both ml-data ml-demo cold analyze ;;
    *)       echo "esperimento sconosciuto: $exp (vedi intestazione dello script)"; exit 2 ;;
    esac
done
