#!/bin/bash
# Lancia il container NCIS per il progetto SDN DoS detection (Linux, macOS, Git Bash).
# Su Windows/PowerShell usare l'equivalente .\run.ps1.
#
#   --privileged : Mininet deve creare interfacce di rete e namespace
#   -v $(pwd):/work : monta il codice del progetto dentro il container
#
# Uso:
#   ./run.sh                               -> shell bash nel container
#   ./run.sh experiments/run_all.sh all    -> esegue un comando nel container
#
# Il container resta attivo ("ncis"): per un secondo terminale  docker exec -it ncis bash
set -e
cd "$(dirname "$0")"
export MSYS_NO_PATHCONV=1                  # Git Bash: non riscrivere i path /work ecc.
SRC=$(pwd -W 2>/dev/null || pwd)           # path Windows sotto Git Bash, POSIX altrove
IMAGE=ncis-sdn:latest

# Moduli kernel per Mininet (OVS + qdisc dei TCLink). Su Docker Desktop vivono nella
# VM e vanno caricati a ogni suo riavvio; su Linux nativo carica quelli dell'host.
docker run --rm --privileged --pid=host debian:11 nsenter -t 1 -m -- \
    sh -c 'modprobe openvswitch && modprobe sch_htb && modprobe sch_netem'

docker image inspect $IMAGE >/dev/null 2>&1 || docker build -t $IMAGE -f docker/Dockerfile .

if [ -z "$(docker ps -q -f name=^ncis$)" ]; then
    docker rm -f ncis >/dev/null 2>&1 || true
    docker run -d --privileged --name ncis -v "$SRC":/work -w /work $IMAGE sleep infinity >/dev/null
fi

if [ $# -gt 0 ]; then docker exec -it ncis bash -c "$*"; else docker exec -it ncis bash; fi
