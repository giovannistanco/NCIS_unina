# Traffic Engineering adattivo in SDN
Rerouting dinamico basato sul monitoraggio delle statistiche OpenFlow, in
ambiente emulato Mininet con switch Open vSwitch e controller Ryu su
OpenFlow 1.3.

## Contenuto

`topology.py` - Topologia Mininet a diamante, configurazione degli host, scenario sperimentale
`controller.py` - SDN Application Ryu: flow entry proattive, monitoraggio, politica di rerouting
`plot.py` - Generazione del grafico dei risultati dal CSV prodotto dal controller

## Prerequisiti

Ambiente di riferimento: VM Ubuntu 22.04 con Python 3.10.


sudo apt install iperf3
pip3 install matplotlib


## Esecuzione

Servono **due terminali**. L'ordine è vincolante: `sudo mn -c` termina fra gli
altri processi anche `ryu-manager`, quindi va eseguito **prima** di avviare il
controller.

**1. Terminale 2 — pulizia**

sudo mn -c

**2. Terminale 1 — controller**

ryu-manager controller.py

Attendere il messaggio `=== Adaptive TE controller avviato ===`.

**3. Terminale 2 — rete e scenario**

sudo python3 topology.py --demo

Sul terminale 1 compaiono le misure, un campione ogni due secondi, e i due
messaggi di rerouting. L'esperimento dura circa 115 secondi; al termine,
uscire dalla CLI Mininet con `exit` e fermare il controller con Ctrl+C.

**Grafico dei risultati**

python3 plot.py /tmp/te_monitor.csv risultati.png

---

## Verifica manuale dello stato del data plane

Da un terzo terminale, mentre la rete è attiva:

# Flow table dello switch di ingresso
sudo ovs-ofctl -O OpenFlow13 dump-flows s1

# Contatori delle porte (gli stessi che legge il controller)
sudo ovs-ofctl -O OpenFlow13 dump-ports s1

Prima del rerouting, l'entry con match
`nw_src=10.0.0.2, nw_dst=10.0.0.4` indica `actions=output:3`; dopo il
rerouting la stessa entry indica `actions=output:4`

---

## Esito atteso

Il flusso A (h1→h3) è di background e resta sempre sul percorso primario.
Il flusso B (h2→h4) è quello elastico, oggetto dello spostamento.

Fase - Traffico - Utilizzo U - Comportamento del controller
0–20 s - A = 2 Mbps - 20 % - nessuna azione, entrambi i flussi sul primario
20–50 s - A + B = 10 Mbps - 100 % - superata la soglia alta, B spostato sul secondario
50–110 s - A = 2 Mbps - 20 % - scesa sotto la soglia bassa, B riportato sul primario

Nella fase centrale i 10 Mbps richiesti saturano il percorso primario, che ha
capacità di 10 Mbps: senza rerouting i due flussi se lo contendono e il flusso B
subisce perdita di pacchetti. Con il rerouting attivo ciascun flusso dispone di
un percorso dedicato e la perdita si annulla. Il confronto è verificabile nei
log di iperf3 in `/tmp/iperf_server_h4.log`.

## Nota sulla ripetizione dello scenario di riferimento

Per ottenere il caso *senza rerouting*, da usare come termine di paragone nel
documento, è sufficiente impostare in `controller.py`:

THRESHOLD_HIGH = 99.0

La condizione di congestione non si verifica mai e i due flussi restano
entrambi sul percorso primario per tutta la durata dell'esperimento.
