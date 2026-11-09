# run.ps1 — lanciatore per Windows (Docker Desktop, backend WSL2).
#
#   .\run.ps1                         -> shell bash nel container
#   .\run.ps1 experiments/run_all.sh all   -> esegue un comando nel container
#   .\run.ps1 -Rebuild ...            -> ricostruisce l'immagine prima
#
# Cosa fa:
#  1. carica nella VM di Docker Desktop i moduli kernel che servono a Mininet
#     (openvswitch per gli switch, sch_htb/sch_netem per i link TCLink). Vanno
#     ricaricati a ogni riavvio di Docker Desktop: per questo lo fa ogni volta.
#  2. costruisce l'immagine ncis-sdn:latest se non esiste.
#  3. avvia (o riusa) il container "ncis" con il codice montato in /work.
param([switch]$Rebuild, [Parameter(ValueFromRemainingArguments = $true)][string[]]$Cmd)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$Image = 'ncis-sdn:latest'

docker info *> $null
if ($LASTEXITCODE -ne 0) { throw "Docker non risponde: avvia Docker Desktop e riprova." }

# nsenter nel namespace di mount del PID 1 = la VM di Docker Desktop, dove stanno i moduli
docker run --rm --privileged --pid=host debian:11 nsenter -t 1 -m -- `
    sh -c 'modprobe openvswitch && modprobe sch_htb && modprobe sch_netem'
if ($LASTEXITCODE -ne 0) { throw "Impossibile caricare i moduli openvswitch/sch_htb/sch_netem." }

docker image inspect $Image *> $null
if ($Rebuild -or $LASTEXITCODE -ne 0) {
    docker build -t $Image -f docker/Dockerfile .
    if ($LASTEXITCODE -ne 0) { throw "Build dell'immagine fallita." }
    docker rm -f ncis *> $null
}

$running = docker ps -q -f name=^ncis$
if (-not $running) {
    docker rm -f ncis *> $null
    docker run -d --privileged --name ncis -v "${PSScriptRoot}:/work" -w /work $Image sleep infinity | Out-Null
}

if ($Cmd) { docker exec -it ncis bash -c ($Cmd -join ' ') }
else      { docker exec -it ncis bash }
