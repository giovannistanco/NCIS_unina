#!/usr/bin/env python3
"""
Topology per il progetto:
"SDN-based Intrusion Detection & Mitigation: ARP Spoofing + Port Scanning"

Host:
  h1, h2   -> host legittimi, comunicano normalmente tra loro e con il server
  h3       -> attaccante (esegue ARP spoofing e/o port scanning verso h4)
  h4       -> server (bersaglio: es. web server / servizio da proteggere)
  h5       -> "quarantine host" (destinazione di remediation: qui possiamo
              simulare una pagina di redirect/log per host messi in
              quarantena invece di bloccarli del tutto)

Switch:
  s1 - collega h1, h2, h3 (rete di accesso)
  s2 - collega h4, h5 (rete server)
  s3 - dorsale tra s1 e s2

Controller:
  c0 - controller remoto Ryu (security_controller.py), OpenFlow 1.3
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info


def build_topology():
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch,
                   link=TCLink, autoSetMacs=True)

    info('*** Aggiungo il controller Ryu remoto\n')
    c0 = net.addController('c0', controller=RemoteController,
                            ip='127.0.0.1', port=6653)

    info('*** Aggiungo gli switch (OpenFlow 1.3)\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')

    info('*** Aggiungo gli host\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')  # attaccante
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')  # server
    h5 = net.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')  # quarantine

    info('*** Creo i link\n')
    net.addLink(h1, s1, bw=10)
    net.addLink(h2, s1, bw=10)
    net.addLink(h3, s1, bw=10)
    net.addLink(h4, s2, bw=10)
    net.addLink(h5, s2, bw=10)
    net.addLink(s1, s3, bw=100)
    net.addLink(s3, s2, bw=100)

    info('*** Avvio la rete\n')
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])

    return net


if __name__ == '__main__':
    setLogLevel('info')
    net = build_topology()
    CLI(net)
    net.stop()
