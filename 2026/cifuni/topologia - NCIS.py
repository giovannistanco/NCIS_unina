#!/usr/bin/python

#https://mininet.org/api/index.html
#https://ryu.readthedocs.io/en/latest/
import threading
import random
import time
from mininet.log import setLogLevel, info
from mininet.topo import Topo
from mininet.net import Mininet, CLI
from mininet.node import OVSKernelSwitch, Host
from mininet.link import TCLink, Link
from mininet.node import RemoteController  # Controller


class Environment(object):
    def __init__(self):
        
        self.net = Mininet(controller=RemoteController, link=TCLink) #traffic control link, usa modulo tc di linux per emulare parametri di rete reali
                                                                     #un link normale userebbe la massima banda disponibile di default
        info("*** Starting controller\n")
        c1 = self.net.addController('c1', controller=RemoteController)  # Controller
        c1.start()

        info("*** Adding hosts\n")
        self.h1 = self.net.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1')
        self.h2 = self.net.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2')
        self.h3 = self.net.addHost('h3', mac='00:00:00:00:00:03', ip='10.0.0.3')
        self.h4 = self.net.addHost('h4', mac='00:00:00:00:00:04', ip='10.0.0.4')

        info("*** Adding switches\n") #ricorda che ovs fa l parte datapath nel kernel
        self.s1 = self.net.addSwitch('s1', cls=OVSKernelSwitch)  # edge switch, lato H1/H2
        self.s2 = self.net.addSwitch('s2', cls=OVSKernelSwitch)  # switch della slice UPPER
        self.s3 = self.net.addSwitch('s3', cls=OVSKernelSwitch)  # switch della slice LOWER
        self.s4 = self.net.addSwitch('s4', cls=OVSKernelSwitch)  # edge switch, lato H3/H4

        info("*** Adding links: host <-> edge switches\n")
        self.net.addLink(self.h1, self.s1, bw=100, delay='0.0025ms')
        self.net.addLink(self.h2, self.s1, bw=100, delay='0.0025ms')
        self.net.addLink(self.h3, self.s4, bw=100, delay='0.0025ms')
        self.net.addLink(self.h4, self.s4, bw=100, delay='0.0025ms')

        info("*** Adding links: UPPER slice S1-S2-S4 (10 Mbps) -> H1 <-> H3\n")
        self.upper1 = self.net.addLink(self.s1, self.s2, bw=10, delay='5ms')
        self.upper2 = self.net.addLink(self.s2, self.s4, bw=10, delay='5ms')

        info("*** Adding links: LOWER slice S1-S3-S4 (1 Mbps) -> H2 <-> H4\n")
        self.lower1 = self.net.addLink(self.s1, self.s3, bw=1, delay='5ms')
        self.lower2 = self.net.addLink(self.s3, self.s4, bw=1, delay='5ms')

        info("*** Starting network\n")
        self.net.build()
        self.net.start()


if __name__ == '__main__':

    setLogLevel('info')
    info('starting the environment\n')
    env = Environment()

    info("*** Running CLI\n")
    CLI(env.net)

    env.net.stop()