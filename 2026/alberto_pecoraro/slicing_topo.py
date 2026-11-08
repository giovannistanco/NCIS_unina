#!/usr/bin/python
from mininet.log import setLogLevel, info
from mininet.net import Mininet, CLI
from mininet.node import OVSKernelSwitch, Host
from mininet.link import TCLink
from mininet.node import RemoteController 

class Environment(object):
    def __init__(self):
        info("*** Creazione della rete SDN per Slicing (Topologia a 6 Switch)\n")
        self.net = Mininet(controller=RemoteController, link=TCLink)
        
        info("*** Avvio del controller remoto\n")
        c1 = self.net.addController('c1', controller=RemoteController) 
        c1.start()
        
        info("*** Aggiunta di host e switch\n")
        # Assegniamo MAC statici per la gestione nel controller
        self.h1 = self.net.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1')
        self.h2 = self.net.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2')
        self.h3 = self.net.addHost('h3', mac='00:00:00:00:00:03', ip='10.0.0.3')
        self.h4 = self.net.addHost('h4', mac='00:00:00:00:00:04', ip='10.0.0.4')
        
        # 6 Switch per una topologia personalizzata
        self.s1 = self.net.addSwitch('s1', cls=OVSKernelSwitch)
        self.s2 = self.net.addSwitch('s2', cls=OVSKernelSwitch)
        self.s3 = self.net.addSwitch('s3', cls=OVSKernelSwitch)
        self.s4 = self.net.addSwitch('s4', cls=OVSKernelSwitch)
        self.s5 = self.net.addSwitch('s5', cls=OVSKernelSwitch)
        self.s6 = self.net.addSwitch('s6', cls=OVSKernelSwitch)
        
        info("*** Creazione dei collegamenti (Links)\n")
        # Collegamenti Host-Switch (Ingresso s1, Uscita s6)
        self.net.addLink(self.h1, self.s1)
        self.net.addLink(self.h2, self.s1)
        self.net.addLink(self.s6, self.h3)
        self.net.addLink(self.s6, self.h4)
        
        # Upper slice (Percorso video ad alta velocità: s1 -> s2 -> s4 -> s6)
        self.net.addLink(self.s1, self.s2, bw=10)
        self.net.addLink(self.s2, self.s4, bw=10)
        self.net.addLink(self.s4, self.s6, bw=10)
        
        # Lower slice (Percorso dati standard a bassa velocità: s1 -> s3 -> s5 -> s6)
        self.net.addLink(self.s1, self.s3, bw=1)
        self.net.addLink(self.s3, self.s5, bw=1)
        self.net.addLink(self.s5, self.s6, bw=1)
        
        info("*** Avvio della rete fisica\n")
        self.net.build()
        self.net.start()

if __name__ == '__main__':
    setLogLevel('info')
    info('*** Inizializzazione Ambiente\n')
    env = Environment()
    info("*** Avvio CLI di Mininet\n")
    CLI(env.net)
    env.net.stop()