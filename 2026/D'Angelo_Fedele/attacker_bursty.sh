#!/bin/bash
# attacker_bursty.sh <ip_vittima> <durata_secondi> <porta_udp>
#
# Genera traffico UDP alternando fasi "a raffica" (bitrate alto) e fasi
# "silenziose" (bitrate basso), invece del classico flood a bitrate costante.
# Serve a testare la soglia adattiva anche su un pattern di attacco non banale
# (un attaccante "furtivo" che resta sotto una soglia fissa nei momenti di
# quiete, ma che un rilevatore basato su media/deviazione standard nella
# finestra recente dovrebbe comunque individuare durante le raffiche).

TARGET=${1:?"uso: attacker_bursty.sh <ip_vittima> <durata_s> <porta>"}
DURATION=${2:-30}
PORT=${3:-5001}

END=$((SECONDS + DURATION))
BURST=1

while [ "$SECONDS" -lt "$END" ]; do
    if [ "$BURST" -eq 1 ]; then
        iperf -c "$TARGET" -u -p "$PORT" -b 100M -w 4M -t 4
        BURST=0
    else
        iperf -c "$TARGET" -u -p "$PORT" -b 0.5m -w 4M -t 4
        BURST=1
    fi
done
