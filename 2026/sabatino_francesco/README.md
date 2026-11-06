# SDN Security Controller

Controller Ryu (OpenFlow 1.3) su una rete Mininet ad anello. Rileva **port scan** e **spoofing**
(ARP, MAC, IP) e risponde in base a un punteggio di rischio: log, deviazione dell'attaccante
su un **honeypot**, **quarantena**. Il blocco viene tolto da solo quando l'host smette.

## File

```
network_config.py   inventario di host e link, percorsi calcolati con BFS
controller.py       app Ryu
topology.py         rete Mininet (4 switch ad anello, 8 host) e servizi su h4/h5
docs/report.pdf     relazione del progetto
docs/topology.png   schema della topologia
```

## Topologia

```
  h1  h2  h3(attaccante)        h6          h4(server)  h5(honeypot)
     \ | /                       |                \      /
     [ s1 ]------------------- [ s3 ]------------- [ s2 ]
        \                                          /
         `---------------- [ s4 ] ----------------'
                           /    \
              h7(attaccante)    h8
```

IP `10.0.0.N`, MAC `00:00:00:00:00:0N`. Link verso gli host 10 Mbit/s, tra switch 100 Mbit/s.

## Avvio

Terminale 1:
```bash
ryu-manager controller.py
```
Terminale 2:
```bash
sudo python3 topology.py
```

## Prove dalla CLI di Mininet

```
pingall                                             # nessun allarme
h3 nmap -n -Pn -sS -T4 10.0.0.4                     # scan del server -> REDIRECT
h3 curl -s 10.0.0.4                                 # risponde l'honeypot
h7 nmap -n -Pn -sS -T4 -p 1-100 10.0.0.1 10.0.0.2   # scan di altri host -> QUARANTINE
h3 arpspoof -i h3-eth0 -t 10.0.0.4 10.0.0.1         # ARP spoofing -> QUARANTINE
sh ovs-ofctl -O OpenFlow13 dump-flows s1            # regole installate
```

Parametri principali (in cima a `controller.py`): soglie 12 / 40 / 70, +2 per ogni nuova
coppia (IP, porta) contattata, +100 per lo spoofing, punteggio dimezzato ogni 30 s,
rilascio dopo 30 s senza traffico bloccato.
