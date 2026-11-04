#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def build():
    net = Mininet(controller=RemoteController, link=TCLink,
                  switch=OVSKernelSwitch, autoSetMacs=False)

    info("*** Controller\n")
    net.addController('c1', controller=RemoteController,
                      ip='127.0.0.1', port=6653)

    info("*** Host\n")
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')  # attaccante
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')  # normale
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')  # server
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')  # normale
    h5 = net.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')  # fidato
    h6 = net.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')  # nodo quarantena


    info("*** Switch\n")
    s1, s2, s3, s4 = [net.addSwitch(f's{i}', protocols='OpenFlow13')
                      for i in range(1, 5)]

    info("*** Link\n")
    # host -> switch: veloci
    for h, s in [(h1, s1), (h4, s1), (h2, s2), (h5, s2), (h3, s4)]:
        net.addLink(h, s, bw=10, delay='0.0025ms')
    # switch -> switch: lenti (S3-S4 e' il collo di bottiglia)
    net.addLink(s1, s3, bw=10, delay='25ms')
    net.addLink(s2, s3, bw=10, delay='25ms')
    net.addLink(s3, s4, bw=6, delay='25ms')
    net.addLink(s1, h6, bw=10)

    return net


if __name__ == '__main__':
    setLogLevel('info')
    net = build()
    net.start()
    CLI(net)
    net.stop()