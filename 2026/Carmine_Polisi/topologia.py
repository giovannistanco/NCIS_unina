
#import threading
#import random
#import time
from mininet.log import setLogLevel, info
#from mininet.topo import Topo
from mininet.net import Mininet, CLI
from mininet.node import OVSKernelSwitch, Host
from mininet.link import TCLink, Link
from mininet.node import RemoteController #Controller esterno, in questo caso userò Ryu

class datacenter(object):
    def __init__(self):
        "Create a data center network"
        self.net = Mininet(controller=RemoteController, link=TCLink) #utilizzerò quindi un controller esterno come ryu e userò traffic control di linux per simulare la banda sui collegamenti virtuali
        info("-avvio del controller \n")
        c1 = self.net.addController('c1', controller=RemoteController) #senza indirizzo ip è sottinteso localhost
        c1.start()
        info("-creazione host \n")
        self.h1 = self.net.addHost('h1',mac='00:00:00:00:00:01', ip='10.0.0.1')
        self.h2 = self.net.addHost('h2',mac='00:00:00:00:00:02' , ip='10.0.0.2')
        self.h3 = self.net.addHost('h3',mac='00:00:00:00:00:03' , ip='10.0.0.3')
        self.h4 = self.net.addHost('h4',mac='00:00:00:00:00:04' , ip='10.0.0.4')
        self.h5 = self.net.addHost('h5',mac='00:00:00:00:00:05' , ip='10.0.0.5')
        self.h6 = self.net.addHost('h6',mac='00:00:00:00:00:06' , ip='10.0.0.6')
        self.h7 = self.net.addHost('h7',mac='00:00:00:00:00:07' , ip='10.0.0.7')
        self.h8 = self.net.addHost('h8',mac='00:00:00:00:00:08' , ip='10.0.0.8')
        self.utente1 = self.net.addHost('utente1',mac='00:00:00:00:00:09' , ip='10.0.0.9')
        self.utente2 = self.net.addHost('utente2',mac='00:00:00:00:00:10' , ip='10.0.0.10')
        self.utente3 = self.net.addHost('utente3',mac='00:00:00:00:00:11' , ip='10.0.0.11')
        self.utenteaut = self.net.addHost('utenteaut',mac='00:00:00:00:00:12' , ip='10.0.0.12')
        self.utenteaut2 = self.net.addHost('utenteaut2',mac='00:00:00:00:00:13' , ip='10.0.0.13')
        info("-creo gli switch spine \n")
        self.spine1 = self.net.addSwitch('s1', cls=OVSKernelSwitch)
        self.spine2 = self.net.addSwitch('s2', cls=OVSKernelSwitch)
        self.spine3 = self.net.addSwitch('s3', cls=OVSKernelSwitch)
        self.spine4 = self.net.addSwitch('s4', cls=OVSKernelSwitch)
        info("-creo gli switch leaf \n")
        self.leaf1 = self.net.addSwitch('s5', cls=OVSKernelSwitch)
        self.leaf2 = self.net.addSwitch('s6', cls=OVSKernelSwitch)
        self.leaf3 = self.net.addSwitch('s7', cls=OVSKernelSwitch)
        self.leaf4 = self.net.addSwitch('s8', cls=OVSKernelSwitch)
        info("-collegamento host con switch leaf(per prova qui utilizzo 10Mbps) \n")
        self.net.addLink(self.h1, self.leaf1, bw=10)
        self.net.addLink(self.h2, self.leaf1, bw=10)
        self.net.addLink(self.h3, self.leaf2, bw=10)
        self.net.addLink(self.h4, self.leaf2, bw=10)
        self.net.addLink(self.h5, self.leaf3, bw=10)
        self.net.addLink(self.h6, self.leaf3, bw=10)
        self.net.addLink(self.h7, self.leaf4, bw=10)
        self.net.addLink(self.h8, self.leaf4, bw=10)
        self.net.addLink(self.utente1, self.leaf1, bw=10)
        self.net.addLink(self.utente2, self.leaf1, bw=10)
        self.net.addLink(self.utente3, self.leaf1, bw=10)
        self.net.addLink(self.utenteaut, self.leaf1, bw=10)
        self.net.addLink(self.utenteaut2, self.leaf1, bw=10)
        info("-collegamento leaf1 e spine full mesh(qui uso collegamenti a 100Mbps) \n")
        self.net.addLink(self.leaf1, self.spine1, bw=100)
        self.net.addLink(self.leaf1, self.spine2, bw=100)
        self.net.addLink(self.leaf1, self.spine3, bw=100)
        self.net.addLink(self.leaf1, self.spine4, bw=100)
        info("-collegamento leaf2 e spine in full mesh(qui uso collegamenti a 100Mbps) \n")
        self.net.addLink(self.leaf2, self.spine1, bw=100)
        self.net.addLink(self.leaf2, self.spine2, bw=100)
        self.net.addLink(self.leaf2, self.spine3, bw=100)
        self.net.addLink(self.leaf2, self.spine4, bw=100)
        info("-collegamento leaf3 e spine in full mesh(qui uso collegamenti a 100Mbps) \n")
        self.net.addLink(self.leaf3, self.spine1, bw=100)
        self.net.addLink(self.leaf3, self.spine2, bw=100)
        self.net.addLink(self.leaf3, self.spine3, bw=100)
        self.net.addLink(self.leaf3, self.spine4, bw=100)
        info("-collegamento leaf4 e spine in full mesh(qui uso collegamenti a 100Mbps) \n")
        self.net.addLink(self.leaf4, self.spine1, bw=100)
        self.net.addLink(self.leaf4, self.spine2, bw=100)
        self.net.addLink(self.leaf4, self.spine3, bw=100)
        self.net.addLink(self.leaf4, self.spine4, bw=100) 
        info("-avvio rete\n")
        self.net.build() #assemblo prima e poi avvio 
        self.net.start()

if __name__ == '__main__':
    setLogLevel('info')
    env = datacenter()
    CLI(env.net) #avvio la cli di mininet per gestire la rete