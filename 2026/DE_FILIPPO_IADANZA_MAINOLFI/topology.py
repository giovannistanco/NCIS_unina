#!/usr/bin/python
from mininet.topo import Topo   
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController 
from mininet.link import TCLink 
from mininet.log import setLogLevel, info 
from functools import partial 
from mininet.cli import CLI


# DEFINIZIONE DEI NODI E DEI COLLEGAMENTI DELLA RETE
class SlicingTopology(Topo): 
    def build(self): 
        # fisso gli indirizzi MAC e IP dei nodi per evitare conflitti
        h1 = self.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1')
        h2 = self.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2')
        h3 = self.addHost('h3', mac='00:00:00:00:00:03', ip='10.0.0.3')
        h4 = self.addHost('h4', mac='00:00:00:00:00:04', ip='10.0.0.4')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')


        # slice 1: h1 -> h3 con larghezza di banda 10 Mbps
        self.addLink(h1, s1, bw=10)
        self.addLink(s1, s2, bw=10)
        self.addLink(s2, s4, bw=10)
        self.addLink(s4, h3, bw=10)

        # slice 2: h2 -> h4 con larghezza di banda 10 Mbps
        # i collegamenti tra s1, s3 e s4 hanno larghezza di banda 1 Mbps
        # questo crea un collo di bottiglia per il traffico tra h2 e h4
        self.addLink(h2, s1, bw=10)
        self.addLink(s1, s3, bw=1)
        self.addLink(s3, s4, bw=1)
        self.addLink(s4, h4, bw=10)



# AVVIO SIMULAZIONE
if __name__ == '__main__':
    setLogLevel('info') # setto i log a info per avere dettagli di avvio più dettagliati durante l'esecuzione nel terminale

    # inizializza la rete con la topologia definita sopra, usando Open vSwitch e un controller remoto
    net = Mininet(
    topo=SlicingTopology(),
    link=TCLink,    
    switch=partial(OVSKernelSwitch, protocols='OpenFlow13'), #costringe gli switch a usare OpenFlow 1.3 per comunicare, necessario per Ryu
    controller=RemoteController('c0', ip='127.0.0.1', port=6633) #forzo il controller a usare l'IP locale e la porta 6633, che è quella di default per Ryu
    ) 

 
    net.start() 
    
    # ADVANCED TRAFFIC GENERATION
    print("\n Inizializzazione percorsi")
    net.pingAll() # Sostituisce pingall

    print(" Avvio dei server iPerf in background su H3 e H4")
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4') 

    # permette di eseguire un comando direttamente su h3
    # iperf -s: crea server iperf (modello client-server)
    # -u: usa UDP invece di TCP
    # -p 9999: imposta la porta del server a 9999
    # -i 1: stampa report ogni secondo
    # &: esegue il comando in background
    h3.cmd('iperf -s -u -p 9999 -i 1 &')
    h4.cmd('iperf -s -u -i 1 &')
    
    import time #per gestire pause temporali 
    time.sleep(2) # pausa per far avviare i server
    
    print(" Generazione del flusso Video (Upper Slice) e Best-Effort (Lower Slice)")
    
    # H1 spara 15 Mbps verso H3 (limitato a 10) per 60 secondi
    # iperf -c: crea client iperf verso h3 (10.0.0.3)
    # -u: usa UDP invece di TCP
    # -p 9999: imposta la porta del server a 9999
    # -b 15M: imposta la banda a 15 Mbps
    # -t 60: imposta la durata a 60 secondi
    h1.cmd('iperf -c 10.0.0.3 -u -p 9999 -b 15M -t 60 &') 
    
    # H2 spara 5 Mbps verso H4 (limitato a 1) per 60 secondi
    h2.cmd('iperf -c 10.0.0.4 -u -b 5M -t 60 &')
    
    print(" Traffico in esecuzione per 60 secondi, guarda la Dashboard\n")
    
    CLI(net)
    net.stop()
