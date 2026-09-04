# Rilevamento e contenimento di lateral movement in SDN

Progetto per l'esame di **Networks and Cloud Infrastructures** — Prof. Giorgio Ventre,
Università degli Studi di Napoli Federico II.

Autore: *Alessandro Gragnaniello*

---

## Cosa fa

`detector.py` è un controller Ryu per OpenFlow 1.3 che estende il learning switch
`simple_switch_13.py` con un monitor delle statistiche di flusso.

In una LAN domestica emulata con Mininet (13 host, uno switch), il controller aggrega
per host, su finestre di 5 secondi, il numero di **ARP Request in broadcast**. Un host
che supera la soglia sta eseguendo una **scansione orizzontale** della sottorete: viene
segnalato con un `ALERT` e isolato installando sullo switch una flow entry di drop.
La regola ha `hard_timeout`, quindi l'host torna operativo da solo alla scadenza,
senza intervento manuale.

Ciò che si rileva è una **firma di traffico**: molti tentativi di
contatto laterale, quasi tutti falliti, ciascuno di volume trascurabile.

Il dettaglio delle scelte progettuali, delle soglie e delle misure è nel report PDF.

## Requisiti

| Componente | Versione usata |
|---|---|
| Sistema | Ubuntu 22.04 LTS |
| Python | 3.10 |
| Mininet | 2.3.0 |
| Open vSwitch | 2.17.12 |
| Ryu | 4.34, in virtualenv |

Mininet e Open vSwitch si installano dai pacchetti della distribuzione o da sorgente
secondo la procedura standard; Ryu va installato nel virtualenv come indicato sotto.

## Installazione

```bash
# 1. virtualenv dedicato per Ryu
python3 -m venv ~/ryu-venv
source ~/ryu-venv/bin/activate

# 2. dipendenze con le versioni verificate
pip install -r Requirements/ryu-requirements.txt

# 3. patch di compatibilità (obbligatoria, vedi sotto)
patch ~/ryu-venv/lib/python3.10/site-packages/ryu/app/wsgi.py \
      < Requirements/ryu-eventlet-patch.diff
```

**Perché la patch.** Ryu 4.34 importa `ALREADY_HANDLED` da `eventlet.wsgi`, simbolo
rimosso in eventlet ≥ 0.33. Senza la patch `ryu-manager` termina con `ImportError`
all'avvio. La patch sostituisce l'import con una sentinella equivalente.

## Prova rapida

Il controller va avviato **prima** della rete: se lo switch non trova nessuno sulla
porta 6653 non completa l'handshake OpenFlow.

**Terminale 1 — controller**

```bash
source ~/ryu-venv/bin/activate
ryu-manager Controller/detector.py
```

Atteso: `instantiating app Controller/detector.py`, poi una riga
`stats reply: N entry` ogni 5 secondi. E' il monitor che richiede le stats allo switch.

**Terminale 2 — rete**

```bash
sudo mn -c                              # pulizia di eventuali istanze precedenti
sudo python3 Topologia/casa.py
```

Al prompt `mininet>`, prima il traffico normale come riferimento, poi la scansione:

```
mininet> h1 ping -c3 h2
mininet> h13 bash -c 'for i in $(seq 1 254); do ping -c1 -W1 10.0.0.$i & done'
```

**Cosa cercare nel terminale 1**, in quest'ordine:

```
window 00:00:00:00:00:0d arp=735 fanout=12 pkts=0     # finestra chiusa, feature aggregate
ALERT HIGH 00:00:00:00:00:0d arp=735 ...              # soglia superata
CONTAIN 00:00:00:00:00:0d dpid=1 prio=100 hard_timeout=30 s
quarantena scaduta 00:00:00:00:00:0d                  # dopo 30 s: riabilitazione
```

`00:00:00:00:00:0d` è il MAC di `h13`. I valori numerici variano fra esecuzioni, la
sequenza degli eventi no. Gli host legittimi restano sotto la soglia
(`arp=0` o `arp=1`) e non compaiono in nessun `ALERT`.

Per verificare il contenimento anche sul data plane, mentre la regola è attiva:

```
mininet> sh sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

La entry con `priority=100` e `dl_src=00:00:00:00:00:0d` non ha azioni: in OpenFlow il
drop è l'assenza di azioni. Scaduto il `hard_timeout` la entry sparisce dalla tabella.

## Struttura

```
Controller/detector.py              controller Ryu
Topologia/casa.py                   topologia Mininet
Requirements/ryu-requirements.txt   dipendenze Python 
Requirements/ryu-eventlet-patch.diff patch di compatibilità per Ryu 4.34
Report_NCIS_finale.pdf              relazione
```
