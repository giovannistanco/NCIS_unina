# L4AntiDoS: Monitoraggio Dinamico e Mitigazione di Attacchi TCP/UDP/ICMP Flooding in Reti SDN

Progetto finale per il corso di Networks and Cloud Infrastructures 

Membri
Simone Valerio (matricola M63001820)
Alessandro Alberino (matricola DE9000116)

---

Obiettivi del Progetto
Nel panorama Software-Defined Networking (SDN), la netta separazione tra il piano di controllo (Control Plane) e il piano dei dati (Data Plane) espone il controllore centrale a possibili vulnerabilità di rete, in particolar modo verso attacchi di tipo Denial of Service (DoS).

Il progetto implementa un meccanismo di difesa automatico e reattivo basato su Ryu Controller e protocollo OpenFlow v1.3 capace di:
1. Rilevare flussi malevoli ad alto volume mediante monitoraggio asincrono con polling ogni `0.5s`.
2. Calcolare soglie di anomalia dinamiche proporzionali alla larghezza di banda impostata sulle singole interfacce (`Threshold = Pkts_Per_Sec * Monitor_Interval`).
3. Isolare tempestivamente l'host attaccante applicando regole OpenFlow di tipo `DROP` a priorità 100 su tutti gli switch, garantendo l'instradamento ininterrotto del traffico lecito.

La determinazione dinamica delle soglie avviene tramite la lettura del file di configurazione `/tmp/port_bw.json`, generato all'istanziazione della classe `MyTopo` in Mininet (con fallback di sicurezza a 20 Mbps in caso di indisponibilità del file).

---

Architettura e Topologia di Rete
Il sistema è validato su una topologia emulata formata da:
-5 Switch logici Open vSwitch: switch edge ($S_1, S_2, S_4, S_5$) collegati allo switch centrale di Core ($S_3$).
-4 Host terminali:
	-`h1` (`00:00:00:00:00:01` - `10.0.0.1`): Host malevolo (attaccante DoS) connesso a S_1.
        -`h2` (`00:00:00:00:00:02` - `10.0.0.2`): Host lecito per la trasmissione di flussi regolari connesso a S_2.
        -`h3` (`00:00:00:00:00:03` - `10.0.0.3`): Server bersaglio (target/vittima) attestato su S_5.
        -`h4` (`00:00:00:00:00:04` - `10.0.0.4`): Host ausiliario connesso a S_4 per la verifica di inoltro multi-nodo.

---

Come Eseguire il Progetto

Prerequisiti Ambiente
-   Oracle VM VirtualBox (Ubuntu Server)
-   Mininet
-   Ryu SDN Framework
-   Iperf / D-ITG

Istruzioni per l'Avvio

1. Avviare il Controller Ryu (Terminale 1):
In un primo terminale avviare il controller con questi comandi:
	cd ~/sdn_antidos_project
	source venv_ryu/bin/activate
	ryu-manager controller_antidos.py
2. Avviare la Topologia Mininet:
In un secondo terminale avviare la rete con questi comandi:
	cd ~/sdn_antidos_project
	sudo mn --custom topology.py --topo mytopo --controller remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow13
3. Esecuzione del Test di Attacco e Mitigazione
	Aprire i due terminali;
	Su terminale di Mininet:
		Avvio del server sulla vittima (h3) in background:
			h3 iperf -s -u -i 1 &
		Lancio dell'attacco flood DoS (h1 verso h3):
			h1 iperf -c 10.0.0.3 -u -b 100M -t 20 &