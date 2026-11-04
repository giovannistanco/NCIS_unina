# SDN Traffic Monitoring & Mitigation con Quarantena (Ryu + Mininet)

Amodio Martina - DE9000018
Catena Maria - DE9000020
Cennamo Antonio - DE9000019

Progetto che implementa, su una rete SDN emulata con **Mininet** e controllata da **Ryu** (OpenFlow 1.3), un sistema di **monitoraggio per corsie (TCP / non-TCP)** e di **mitigazione automatica** del traffico anomalo. Quando un host supera le soglie di banda per un numero di intervalli consecutivi, il controller installa una regola di mitigazione che può:

- **scartare** il traffico dell'host (drop), oppure
- **dirottarlo in quarantena** su un host di ispezione (`h6`), dove viene catturato con `tcpdump` per l'analisi forense.

Il blocco ha una durata limitata (timeout di sblocco) e, dopo lo sblocco, gli host recidivi vengono ribloccati rapidamente.

---

## Indice

1. [Architettura](#1-architettura)
2. [Prerequisiti e istruzioni di esecuzione](#2-prerequisiti-e-istruzioni-di-esecuzione)
3. [Configurazione del controller](#3-configurazione-del-controller)
4. [Output e risultati](#4-output-e-risultati)
5. [Verifica delle regole installate](#5-verifica-delle-regole-installate)
6. [Troubleshooting](#6-troubleshooting)

---

## 1. Architettura

### Pipeline OpenFlow a due tabelle

**Tabella 0: misura e mitigazione**

| Priorità | Match | Azione | Cookie | Quando viene installata |
|---|---|---|---|---|
| 200 | `eth_type=0x0800`, `ipv4_src=<IP host>`, `ip_proto=6` (TCP) o `17` (UDP) | Quarantena su `h6` oppure drop | `0x99` | Dinamicamente, in caso di allarme (`hard_timeout`) |
| 100 | `in_port=<porta accesso>`, `eth_type=0x0800`, `ip_proto=6` | `goto_table 1` | `0x20` | All'avvio, una per porta di accesso (corsia **TCP**) |
| 50 | `in_port=<porta accesso>` | `goto_table 1` | `0x10` | All'avvio, una per porta di accesso (corsia **NON-TCP**) |
| 0 | qualsiasi | `goto_table 1` | n/a | All'avvio |

**Tabella 1: forwarding L2**

- Regole di learning switch (da `simple_switch_13`, installate in `table_id=1`).
- Table-miss (priorità 0): invio al controller.

### Logica di rilevamento

1. Ogni **2 secondi** (`INTERVAL`) il controller richiede le statistiche dei flussi della Tabella 0.
2. Dalla differenza di `byte_count` tra due letture calcola il rate (B/s) per ogni coppia *porta di accesso / corsia*.
3. Se il rate supera la soglia per un numero di intervalli consecutivi, scatta l'allarme e viene installata la regola a priorità 200.
4. Allo scadere dell'`hard_timeout`, lo switch invia un `FlowRemoved`: il controller ripristina lo stato e, con `FAST_REBLOCK`, ri-applica rapidamente la mitigazione se l'host torna a sforare.

| Corsia | Soglia | Intervalli consecutivi | Tempo approssimativo |
|---|---|---|---|
| TCP | 625 000 B/s (5.0 Mbit/s) | 10 | ~20 s |
| NON-TCP | 200 000 B/s (1.6 Mbit/s) | 3 | ~6 s |

Gli host in **whitelist** (`h3`, `h5`, `h6`) sono esenti dall'allarme.

### Host e porte di accesso monitorate

| Switch | Porta | Host | IP |
|---|---|---|---|
| s1 | 1 | h1 | 10.0.0.1 |
| s1 | 2 | h4 | 10.0.0.4 |
| s1 | 4 | h6 (quarantena) | 10.0.0.6 |
| s2 | 1 | h2 | 10.0.0.2 |
| s2 | 2 | h5 | 10.0.0.5 |
| s4 | 1 | h3 | 10.0.0.3 |

> La porta 4 di s1 è quella a cui è collegato `h6`; le porte monitorate sono quelle definite in `ACCESS_PORTS` nel controller.

---

## 2. Prerequisiti e istruzioni di esecuzione

### 2.1 Ambiente di esecuzione (Macchina Virtuale)

| Componente | Versione / Valore |
|---|---|
| Sistema operativo | Ubuntu 22.04 LTS |
| Mininet | 2.3.0 |
| Python | 3.10.12 |
| RAM | 4 GB |
| CPU | 3 core |
| Rete della VM | NAT |

### 2.2 Dipendenze software

```bash
sudo apt install vim
sudo apt install git
sudo apt install python3-pip
sudo pip install ryu
```

Per eseguire i test servono inoltre `mininet`, `iperf` e `tcpdump` (normalmente inclusi nell'installazione di Mininet).

### 2.3 Struttura del repository

```
.
├── topologia.py                  # Script Mininet: crea host, switch e link
├── controller_mitigation.py      # Applicazione Ryu: monitoraggio e mitigazione SDN
├── run_test.sh                   # Script che lancia i test di traffico
├── fase9_analisi_confronto.py    # Analisi dei risultati e generazione grafici
├── genera_grafico_html.py        # Generazione del grafico interattivo
├── grafico.html                  # Grafico HTML generato
└── results/                      # Risultati: log iperf, CSV, pcap
```

### 2.4 Istruzioni di esecuzione (Quickstart)

**1. Avviare il controller** (terminale 1):

```bash
ryu-manager controller_mitigation.py
```

**2. Avviare la topologia Mininet** (terminale 2):

```bash
sudo python3 topologia.py
```

**3. Aprire i terminali Xterm** degli host necessari dalla CLI Mininet (ad esempio `xterm h1 h2 h6`).

**4. Avviare il monitoraggio forense su h6** (CLI Mininet):

```bash
mininet> h6 tcpdump -i h6-eth0 -w results/h6_quarantena.pcap &
```

**5. Eseguire il test** (CLI Mininet):

```bash
mininet> sh ./run_test.sh
```

**6. Analizzare i risultati** al termine del test:

```bash
python3 fase9_analisi_confronto.py
```

---

## 3. Configurazione del controller

I parametri principali si trovano in cima a `controller_mitigation.py`.

| Parametro | Default | Descrizione |
|---|---|---|
| `INTERVAL` | `2` | Intervallo di polling delle statistiche (s) |
| `THRESHOLD_TCP` / `CONSECUTIVE_TCP` | `625000` / `10` | Soglia (B/s) e intervalli consecutivi per la corsia TCP |
| `THRESHOLD_NON_TCP` / `CONSECUTIVE_NON_TCP` | `200000` / `3` | Soglia (B/s) e intervalli consecutivi per la corsia NON-TCP |
| `BLOCK_HARD_TIMEOUT` | `15` | Durata del blocco/quarantena (s) |
| `FAST_REBLOCK` | `True` | Riblocco rapido dei recidivi dopo lo sblocco |
| `ENABLE_QUARANTINE` | `True` | `True`: dirotta su h6; `False`: drop puro |
| `QUARANTINE_DPID` / `QUARANTINE_PORT` | `1` / `4` | Switch e porta a cui è collegato h6 |
| `WHITELIST` | `{h3, h5, h6}` | Host esenti dalla mitigazione |

### Modalità di mitigazione

- **Quarantena** (`ENABLE_QUARANTINE = True`, host su s1): il flusso viene riscritto (`eth_dst` e `ipv4_dst` di h6) e inviato sulla porta di h6.
- **Drop** (`ENABLE_QUARANTINE = False`, oppure host su uno switch diverso da quello di quarantena): il flusso viene scartato.

### Limitazioni note

- La mitigazione della corsia NON-TCP fa match solo su **UDP** (`ip_proto=17`): traffico ICMP o ARP, pur contato nella corsia, non viene bloccato.
- La quarantena è attiva solo per gli host collegati allo switch `QUARANTINE_DPID`; per gli altri si applica il drop.

---

## 4. Output e risultati

- **Console del controller**: tabella per switch con porta, host, corsia, rate, contatore, stato e nota, aggiornata a ogni intervallo; log di allarme, installazione regola e sblocco.
- **`monitor_mitigation.csv`**: serie temporale con le colonne `t_s, dpid, port, host, lane, rx_Bps, rx_Mbps, counter, state, nota`. Stati possibili: `NORMALE`, `ALLARME`, `BLOCCATO`.
- **`results/`**: log `iperf`, CSV e cattura `h6_quarantena.pcap`.
- **`grafico.html`**: grafico generato da `genera_grafico_html.py`.

---

## 5. Verifica delle regole installate

Durante l'esecuzione, per ispezionare le tabelle di flusso di uno switch (ad esempio s1):

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

Per vedere solo la Tabella 0:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 table=0
```

Le regole di mitigazione si riconoscono dalla priorità `200` e dal cookie `0x99`.

---

## 6. Troubleshooting

- **Pulizia di Mininet** in caso di errori o interruzioni: `sudo mn -c`
- **Il controller non vede gli switch**: avviare sempre Ryu *prima* di Mininet e verificare che la topologia usi un controller remoto sulla porta `6653`.
- **Errori all'avvio di Ryu su Python 3.10** (ad esempio legati a `eventlet`): in alcuni ambienti serve una versione compatibile di `eventlet` (es. `pip install eventlet==0.30.2`).
- **Permessi sul file pcap**: assicurarsi che la cartella `results/` esista prima di lanciare `tcpdump`.
