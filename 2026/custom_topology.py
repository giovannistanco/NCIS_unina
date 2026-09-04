#!/usr/bin/env python3
"""
Topologia custom per il Project Work SDN (Mininet + Ryu)
Struttura con switch OpenFlow e host differenziati (Leciti vs Attaccanti).
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

class ProjectTopo(Topo):
    def build(self):
        # Aggiunta Switch OpenFlow 1.3
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')
        s4 = self.addSwitch('s4', protocols='OpenFlow13')

        # Aggiunta Host
        # H1: Attaccante (DoS UDP/Flood)
        # H4: Host lecito collegato allo stesso switch di bordo S1
        # H2: Host lecito collegato a S2
        # H3: Server Target (destinatario del traffico)
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

        # Collegamenti Host-Switch (con limiti di banda e ritardo)
        self.addLink(h1, s1, bw=10, delay='1ms')
        self.addLink(h4, s1, bw=10, delay='1ms')
        self.addLink(h2, s2, bw=10, delay='1ms')
        self.addLink(h3, s4, bw=10, delay='1ms')

        # Collegamenti Inter-Switch (Infrastruttura di rete)
        self.addLink(s1, s3, bw=10, delay='2ms')
        self.addLink(s2, s3, bw=10, delay='2ms')
        self.addLink(s3, s4, bw=10, delay='2ms')

def run():
    topo = ProjectTopo()
    # Connessione al Ryu Controller remoto in ascolto sulla porta standard 6653 o 6633
    net = Mininet(topo=topo, link=TCLink, switch=OVSSwitch, controller=None)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    
    net.start()
    info('*** Rete avviata. Controller atteso su 127.0.0.1:6633\n')
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
