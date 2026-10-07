#!/usr/bin/python
"""
Topologia SDN per la simulazione DoS detection/mitigation.

Struttura:
    h1 --- s1 ---\
                   s3 --- s4 --- h3   (server)
    h2 --- s2 ---/

- h1, h2 : host client, collegati ognuno a un proprio switch di accesso (s1, s2)
- h3     : host server, collegato allo switch s4
- s1, s2 : switch di accesso (un solo host client ciascuno)
- s3, s4 : switch "core"/backbone, attraversati dal traffico aggregato di h1+h2

Il controller Ryu (RemoteController) DEVE essere già in esecuzione
(`ryu-manager controller.py`) prima di lanciare questo script, perché
Mininet si limita a collegarsi a un controller remoto già attivo.
"""

from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.link import TCLink


# Banda dei link (Mbit/s), coerente con la tabella nel README
BW_CLIENT_TO_SWITCH = 10   # h1/h2 -> s1/s2
BW_BACKBONE = 12           # s3 <-> s4
BW_SWITCH_TO_SERVER = 12   # s4 -> h3


class Environment(object):
    """Costruisce, avvia e mette a disposizione la rete Mininet."""

    def __init__(self):
        self.net = Mininet(controller=RemoteController, link=TCLink)

        info("*** Starting controller\n")
        # Il controller è remoto: ci si aspetta che ryu-manager sia già avviato
        # sull'indirizzo/porta di default (127.0.0.1:6653).
        c1 = self.net.addController('c1', controller=RemoteController)
        c1.start()

        info("*** Adding hosts\n")
        self.h1 = self.net.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1')
        self.h2 = self.net.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2')
        self.h3 = self.net.addHost('h3', mac='00:00:00:00:00:03', ip='10.0.0.3')

        info("*** Adding switches\n")
        self.s1 = self.net.addSwitch('s1', cls=OVSKernelSwitch)
        self.s2 = self.net.addSwitch('s2', cls=OVSKernelSwitch)
        self.s3 = self.net.addSwitch('s3', cls=OVSKernelSwitch)
        self.s4 = self.net.addSwitch('s4', cls=OVSKernelSwitch)

        info("*** Adding links\n")
        # Accesso client -> switch di accesso
        self.net.addLink(self.h1, self.s1, bw=BW_CLIENT_TO_SWITCH)
        self.net.addLink(self.h2, self.s2, bw=BW_CLIENT_TO_SWITCH)

        # Switch di accesso -> core (stessa banda dell'accesso: qui non si
        # aggrega ancora traffico di più host)
        self.net.addLink(self.s1, self.s3, bw=BW_CLIENT_TO_SWITCH)
        self.net.addLink(self.s2, self.s3, bw=BW_CLIENT_TO_SWITCH)

        # Backbone core <-> core, attraversato dal traffico aggregato di h1+h2
        self.net.addLink(self.s3, self.s4, bw=BW_BACKBONE)

        # Switch core -> server
        self.net.addLink(self.s4, self.h3, bw=BW_SWITCH_TO_SERVER)

        info("*** Starting network\n")
        self.net.build()
        self.net.start()

        info("*** Testing connectivity (pingAll)\n")
        # Necessario per popolare le forwarding table degli switch prima di
        # generare traffico applicativo (iperf/D-ITG) e testare il blocco DoS.
        self.net.pingAll()
        info("*** Showing rules learned by switches\n")
        for switch in self.net.switches:
            info('*Switch %s*\n' % switch.name)
            info(switch.cmd('ovs-ofctl dump-flows ' + switch.name))


if __name__ == '__main__':
    setLogLevel('info')
    info('*** Starting the environment\n')
    env = Environment() # 1. costruisce e avvia la rete (build, start, ecc.)

    info("*** Running CLI\n")
    CLI(env.net)  # 2. fornisce il controllo interattivo

    info("*** Stopping network\n")
    env.net.stop()
