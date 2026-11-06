#!/usr/bin/python3
"""Topologia Mininet per il progetto SDN DoS detection.

5 switch con un CICLO (s2-s3-s4-s2) per testare la robustezza del forwarding.
- Server:          hsrv su s4
- Attaccanti:      a1 su s1, a2 su s5  (switch DIVERSI -> attacco distribuito)
- Utenti legittimi: u1 su s1 (stesso switch di a1 -> caso "piracy shield"), u2 su s5
- Link s3<->s4 a 7 Mbps: STP rompe il ciclo bloccando la porta s3-eth2 (s3 verso s4;
  stplib installa su s3 la regola "in_port=s3-eth2 actions=drop"). Il traffico verso
  hsrv passa quindi s1-s2-s4 e non attraversa mai s3-s4.
  Il collo di bottiglia EFFETTIVO negli esperimenti e' l'uplink s1<->s2 (10 Mbps),
  condiviso da u1 e a1. `--test` lo verifica coi contatori delle porte.

Uso:
    sudo python3 topology.py            # avvia la CLI Mininet (per screenshot/uso manuale)
    sudo python3 topology.py --test     # modalita' automatica: attende STP, pingall, verifica percorso, exit
"""
import sys
import time

from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.link import TCLink

PACKET_IN_RATE = 200     # packet-in/s per switch verso il controller (minimo OVS: 100)
PACKET_IN_BURST = 50


class DoSTopo:
    def __init__(self):
        self.net = Mininet(controller=RemoteController, link=TCLink,
                           switch=OVSKernelSwitch, autoSetMacs=False)
        info("*** Controller\n")
        self.net.addController('c0', controller=RemoteController,
                               ip='127.0.0.1', port=6653)
        info("*** Hosts\n")
        self.h_srv = self.net.addHost('hsrv', mac='00:00:00:00:00:10', ip='10.0.0.100')
        self.u1 = self.net.addHost('u1', mac='00:00:00:00:00:01', ip='10.0.0.1')
        self.u2 = self.net.addHost('u2', mac='00:00:00:00:00:02', ip='10.0.0.2')
        self.a1 = self.net.addHost('a1', mac='00:00:00:00:00:f1', ip='10.0.0.241')
        self.a2 = self.net.addHost('a2', mac='00:00:00:00:00:f2', ip='10.0.0.242')
        info("*** Switches\n")
        s = {n: self.net.addSwitch(n) for n in ['s1', 's2', 's3', 's4', 's5']}
        self.s = s
        info("*** Links\n")
        # accessi host (alta banda, basso delay)
        self.net.addLink(self.u1, s['s1'], bw=10, delay='0.1ms')
        self.net.addLink(self.a1, s['s1'], bw=10, delay='0.1ms')
        self.net.addLink(self.u2, s['s5'], bw=10, delay='0.1ms')
        self.net.addLink(self.a2, s['s5'], bw=10, delay='0.1ms')
        self.net.addLink(self.h_srv, s['s4'], bw=10, delay='0.1ms')
        # core con CICLO s2-s3-s4-s2
        self.net.addLink(s['s1'], s['s2'], bw=10, delay='5ms')
        self.net.addLink(s['s5'], s['s2'], bw=10, delay='5ms')
        self.net.addLink(s['s2'], s['s3'], bw=10, delay='5ms')
        self.net.addLink(s['s3'], s['s4'], bw=7,  delay='5ms')   # bloccato da STP (vedi sopra)
        self.net.addLink(s['s4'], s['s2'], bw=10, delay='5ms')   # chiude il ciclo
        self.net.build()
        self.net.start()
        # Protezione del piano di controllo: OVS inoltra a Ryu al piu' PACKET_IN_RATE
        # packet-in/s per switch (raffica max PACKET_IN_BURST), il resto lo scarta lo
        # switch. Copre l'attaccante che cambia MAC a ogni pacchetto: ogni MAC nuovo
        # e' un table-miss. BPDU STP e ARP stanno molto sotto il limite.
        for sw in s.values():
            sw.cmd('ovs-vsctl set controller %s controller_rate_limit=%d '
                   'controller_burst_limit=%d' % (sw.name, PACKET_IN_RATE, PACKET_IN_BURST))


def check_path(topo):
    """Verifica quale ramo del ciclo usa il traffico u1->hsrv: confronta i byte
    ricevuti da ciascun lato prima/dopo 5 s di iperf. Il link senza crescita e'
    quello bloccato da STP."""
    hsrv, u1 = topo.h_srv, topo.u1
    links = {'s2-s4': ('s4', 's2'), 's3-s4': ('s4', 's3'), 's2-s3': ('s3', 's2')}

    def rx_bytes_from(sw, peer):
        intf = topo.s[sw].connectionsTo(topo.s[peer])[0][0]
        return int(topo.s[sw].cmd('cat /sys/class/net/%s/statistics/rx_bytes' % intf) or 0)

    before = {k: rx_bytes_from(*v) for k, v in links.items()}
    hsrv.cmd('iperf -s -p 5099 > /dev/null 2>&1 &')
    time.sleep(1)
    u1.cmd('iperf -c 10.0.0.100 -p 5099 -t 5 > /dev/null 2>&1')
    hsrv.cmd('kill %iperf')
    print("*** [TEST] byte ricevuti per link durante 5 s di iperf u1->hsrv:", flush=True)
    for k, v in links.items():
        print("    %-6s %10d" % (k, rx_bytes_from(*v) - before[k]), flush=True)
    # stplib blocca una porta installando una regola di drop su in_port
    print("*** [TEST] porte bloccate da STP:", flush=True)
    for sw in ('s2', 's3', 's4'):
        out = topo.s[sw].cmd('ovs-ofctl -O OpenFlow13 dump-flows %s | grep "actions=drop"' % sw)
        print("    %s: %s" % (sw, out.strip() or '-'), flush=True)


def run_test(topo):
    """Attende la convergenza STP, esegue pingall e un dump flow. Ritorna exit code."""
    net = topo.net
    info("*** [TEST] Attendo la convergenza STP (il ciclo richiede ~35s)\n")
    time.sleep(35)
    # warm-up: la prima pingall popola gli L2-learning e l'ARP
    info("*** [TEST] pingall di warm-up\n")
    net.pingAll()
    # misura reale
    info("*** [TEST] pingall di misura\n")
    dropped = net.pingAll()  # ritorna la percentuale di pacchetti persi
    check_path(topo)
    print("*** [TEST] net (link):", flush=True)
    for link in net.links:
        print("   ", link, flush=True)
    net.stop()
    if dropped == 0:
        print("*** [TEST] RESULT: 0% dropped — reachability OK", flush=True)
        return 0
    print("*** [TEST] RESULT: %.0f%% dropped — FAIL" % dropped, flush=True)
    return 1


if __name__ == '__main__':
    setLogLevel('info')
    topo = DoSTopo()
    if '--test' in sys.argv:
        code = run_test(topo)
        sys.exit(code)
    CLI(topo.net)
    topo.net.stop()
