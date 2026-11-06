#!/usr/bin/env python3

"""
Topologia Mininet per il progetto "Adaptive Distributed DoS Detection & Mitigation
in SDN".

    H1 (attaccante)         -- S1
    H2 (legittimo TCP)      -- S1
    H3 (attaccante)         -- S3
    H4 (legittimo TCP)      -- S4
    H5 (vittima/server)     -- S5
    H6 (legittimo TCP)      -- S6
    H7 (legittimo UDP late) -- S6

Anello: s1-s2-s3-s4-s5-s6-s1
Uso:
    sudo python3 topology.py
    sudo python3 topology.py --auto
    sudo python3 topology.py --auto --duration 45 --att 1
"""

import argparse
import os
import time

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RING_LINK_BW = 10           # Mbps, velocità dei collegamenti fra gli switch
STP_CONVERGENCE_WAIT = 35   #secondi, tempo di convergenza per STP
OF_VERSION = 'OpenFlow13'   # usato per ovs-ofctl
LEGIT_UDP_PORT = 5004       # Porta UDP legittima presente in WHITELIST_UDP_PORTS
WARMUP_TIME = 20            # Finestra di calibrazione dedicata agli host legittimi iniziali


from mininet.link import TCLink
import subprocess


class DosTopo(Topo):
    def build(self):
        #inizializzazione switch
        switches = {}
        for i in range(1, 7):
            switches[i] = self.addSwitch('s%d' % i, cls=OVSSwitch,
                                         protocols=OF_VERSION)

        #connessione fra switch
        ring_pairs = [(1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 1)]
        for a, b in ring_pairs:
            self.addLink(switches[a], switches[b], bw=RING_LINK_BW)

        #inizializzazione host
        host_specs = [
            ('h1', 1, '10.0.0.1'),
            ('h2', 1, '10.0.0.2'),
            ('h3', 3, '10.0.0.3'),
            ('h4', 4, '10.0.0.4'),
            ('h5', 5, '10.0.0.5'),
            ('h6', 6, '10.0.0.6'),
            ('h7', 6, '10.0.0.7'),
        ]

        #connessione host-switch
        for name, sw_idx, ip in host_specs:
            host = self.addHost(name, ip=ip + '/24')
            self.addLink(host, switches[sw_idx])


def enable_stp(net):
    """Abilita STP e forza una gerarchia deterministica per il Root Bridge."""
    # Le priorità STP vanno a multipli di 4096. Più basso = maggiore priorità.
    prio = 4096
    for i in range(1, 7):
        sw_name = 's%d' % i
        sw = net.get(sw_name)
        sw.cmd('ovs-vsctl set bridge %s stp_enable=true' % sw.name)
        sw.cmd('ovs-vsctl set bridge %s other_config:stp-priority=%d' % (sw.name, prio))
        prio += 4096  # S1=4096, S2=8192, S3=12288, S4=16384, ecc.

    info('*** Attendo %ds per la convergenza di STP...\n'
         % STP_CONVERGENCE_WAIT)
    time.sleep(STP_CONVERGENCE_WAIT)


def run_auto_experiment(net, duration=30, att=0):
    h1, h2, h3, h4, h5, h6, h7 = (net.get(n) for n in
                                  ('h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7'))
    s1, s6 = net.get('s1'), net.get('s6')

    # Avvio del Server h5 
    info('*** Avvio server iperf su h5 (UDP attacco:5001, TCP legit:5002, UDP legit:%d)\n'
         % LEGIT_UDP_PORT)
    h5.cmd('pkill -f "iperf -s" 2>/dev/null')
    time.sleep(0.5)
    h5.cmd('iperf -s -u -p 5001 > /tmp/h5_udp_attack_server.log 2>&1 &')
    h5.cmd('iperf -s -p 5002 > /tmp/h5_tcp_server.log 2>&1 &')
    h5.cmd('iperf -s -u -p %d -i 1 > /tmp/h5_udp_legit_server.log 2>&1 &' % LEGIT_UDP_PORT)
    time.sleep(1)
   

    # Avvio il solo traffico legittimo iniziale 
    total_legit_duration = duration + WARMUP_TIME

    info('*** Avvio traffico legittimo iniziale (h2, h4, h6 -> h5 TCP per %ds)\n' % total_legit_duration)
    for legit in (h2, h4, h6):
        legit.cmd('iperf -c %s -p 5002 -b 2M -t %d -i 1 > /tmp/%s_legit.log 2>&1 &'
                  % (h5.IP(), total_legit_duration, legit.name))

        # ss -ti con snapshot ogni secondo (cwnd, rtt, retrans)
        legit.cmd('( for i in $(seq 1 %d); do echo "=== T=$i ==="; '
                  'ss -ti dst %s; sleep 1; done ) > /tmp/%s_ss.log 2>&1 &'
                  % (total_legit_duration, h5.IP(), legit.name))

    info('*** Attesa calibrazione baseline controller sul traffico lecito (%ds)...\n' % WARMUP_TIME)
    time.sleep(WARMUP_TIME)

    # Ingresso di h7 dopo il warm-up (Traffico UDP legittimo su porta in whitelist)
    info('*** Avvio flusso UDP legittimo (h7 -> h5:%d per %ds)\n'
         % (LEGIT_UDP_PORT, duration))
    h7.cmd('iperf -c %s -u -p %d -b 2M -t %d -i 1 > /tmp/h7_udp_legit.log 2>&1 &'
           % (h5.IP(), LEGIT_UDP_PORT, duration))
    h7.cmd('( for i in $(seq 1 %d); do echo "=== T=$i ==="; '
                  'ss -ti dst %s; sleep 1; done ) > /tmp/h7_ss.log 2>&1 &'
                  % (duration, h5.IP()))

    # Avvio dell'eventuale attacco
    if att == 1:
        info('*** Avvio attacco (h1 flood costante 100M su UDP:5001)\n')
        h1.cmd('iperf -c %s -u -p 5001 -b 100M -w 4M -t %d '
               '> /tmp/h1_attack.log 2>&1 &' % (h5.IP(), duration))

    elif att == 2:
        info('*** Avvio attacco (h3 attacco a burst su UDP:5001)\n')
        attacker_script = os.path.join(SCRIPT_DIR, 'attacker_bursty.sh')
        h3.cmd('bash %s %s %d 5001 > /tmp/h3_attack.log 2>&1 &'
               % (attacker_script, h5.IP(), duration))

    elif att == 3:
        attacker_script = os.path.join(SCRIPT_DIR, 'attacker_bursty.sh')
        info('*** Avvio attacco (h1 flood costante 100M su UDP:5001 e h3 attacco a burst su UDP:5001)\n')
        
        h3.cmd('bash %s %s %d 5001 > /tmp/h3_attack.log 2>&1 &'
               % (attacker_script, h5.IP(), duration))
        h1.cmd('iperf -c %s -u -p 5001 -b 100M -w 4M -t %d '
               '> /tmp/h1_attack.log 2>&1 &' % (h5.IP(), duration))
    else:
        info('*** Nessun attacco\n')

    info('*** Esperimento in corso per %ds\n' % duration)
    time.sleep(duration + 3)

    info('*** Esperimento completato.\n')
    info('*** File generati in /tmp/:\n'
         '      h2_legit.log, h4_legit.log, h6_legit.log, h7_udp_legit.log\n'
         '      h2_ss.log, h4_ss.log, h6_ss.log\n'
         '      h5_udp_attack_server.log, h5_udp_legit_server.log, h5_tcp_server.log\n'
         '      s1_ports_before.log, s1_ports_after.log\n'
         '      s6_ports_before.log, s6_ports_after.log\n')


def main():
    parser = argparse.ArgumentParser(description='Topologia DoS SDN')
    parser.add_argument('--auto', action='store_true')
    parser.add_argument('--duration', type=int, default=30)
    parser.add_argument('--att', type=int, default=0)

    args = parser.parse_args()
    setLogLevel('info')

    topo = DosTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None, autoSetMacs=True)
    net.addController('c0', controller=RemoteController,
                      ip='127.0.0.1', port=6653)

    net.start()
    enable_stp(net)

    info('*** pingall\n')
    net.pingAll()

    try:
        if args.auto:
            run_auto_experiment(net, duration=args.duration, att=args.att)
        CLI(net)
    finally:
        net.stop()


if __name__ == '__main__':
    main()

