# Topologia Mininet: 4 switch ad anello (s1-s3-s2-s4-s1) e 8 host, presi da network_config.py

import os
import sys

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from network_config import HOSTS, SWITCH_LINKS

# porte aperte sull'honeypot: più servizi del server vero, per attirare l'attaccante
HONEYPOT_PORTS = [21, 22, 23, 80, 8080]


def build_network():
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink,
                  autoSetMacs=False, build=False)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)

    # failMode secure: senza controller lo switch non fa il learning switch da solo
    dpids = sorted({h.dpid for h in HOSTS})
    switches = {}
    for d in dpids:
        switches[d] = net.addSwitch("s%d" % d, protocols="OpenFlow13", failMode="secure",
                                    dpid="%016x" % d)

    hosts = {}
    for h in HOSTS:
        hosts[h.name] = net.addHost(h.name, ip=h.ip + "/24", mac=h.mac)

    # i numeri di porta vanno imposti: il controller si basa sull'inventario
    for h in HOSTS:
        net.addLink(hosts[h.name], switches[h.dpid], port2=h.port, bw=10)
    for a, pa, b, pb in SWITCH_LINKS:
        net.addLink(switches[a], switches[b], port1=pa, port2=pb, bw=100)

    net.start()
    for h in hosts.values():
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null")   # niente traffico IPv6
    return net


def start_services(net):
    # server vero h4: pagina web sulla porta 80 e iperf sulla 5001
    h4 = net.get("h4")
    h4.cmd("mkdir -p /tmp/h4web && echo 'server h4' > /tmp/h4web/index.html")
    h4.cmd("python3 -m http.server 80 --directory /tmp/h4web > /tmp/h4_http.log 2>&1 &")
    h4.cmd("iperf -s -p 5001 > /tmp/h4_iperf.log 2>&1 &")

    # honeypot h5: pagina diversa, così si vede subito se una richiesta è stata deviata
    h5 = net.get("h5")
    h5.cmd("mkdir -p /tmp/h5web && echo 'server h4 (honeypot h5)' > /tmp/h5web/index.html")
    for p in HONEYPOT_PORTS:
        h5.cmd("python3 -m http.server %d --directory /tmp/h5web > /tmp/h5_http_%d.log 2>&1 &" % (p, p))
    info("*** servizi avviati: h4 (http 80, iperf 5001), h5 honeypot (porte %s)\n" % HONEYPOT_PORTS)


if __name__ == "__main__":
    setLogLevel("info")
    network = build_network()
    start_services(network)
    CLI(network)
    network.stop()
