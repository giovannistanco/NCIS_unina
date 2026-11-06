#!/usr/bin/python3
"""Scena di una casistica della demo, eseguita in automatico.

Avviato da experiments/demo_screens.sh con il controller gia' acceso nella
configurazione della casistica. Passi:
  1. rete, attesa di STP, server iperf su hsrv, download TCP di u1;
  2. ping di u1 e a1 prima dell'attacco;
  3. flood di a1: 'big' = UDP 25 Mbps a pacchetti da 1470 B,
                  'small' = UDP 5 Mbps a pacchetti da 250 B;
  4. se la mitigazione e' attiva aspetta il BLOCK (max 60 s), altrimenti 25 s;
     poi ping di u1 e a1;
  5. regola di drop su s1, poi altri 20 s di traffico.
Uscite in <out>/<nome>.txt.

Uso: sudo python3 experiments/demo_screens.py <cartella_output> <big|small> <attendi_block 0|1>
"""
import os
import sys
import time

from mininet.log import setLogLevel, info

sys.path.insert(0, '.')
from topology import DoSTopo  # noqa: E402

SRV = '10.0.0.100'
FLOOD = {'big': '-b 25M', 'small': '-b 5M -l 250'}


def save(out, name, text):
    with open(os.path.join(out, name + '.txt'), 'w') as f:
        f.write(text)


def blocked(out):
    path = os.path.join(out, 'eventi.csv')
    if not os.path.exists(path):
        return False
    with open(path) as f:
        return any(',BLOCK,' in line for line in f)


def ping(host, name):
    return 'mininet> %s ping -c 3 hsrv\n%s' % (name, host.cmd('ping -c 3 %s' % SRV))


def main(out, flood, wait_block):
    topo = DoSTopo()
    net = topo.net
    hsrv, u1, a1, s1 = topo.h_srv, topo.u1, topo.a1, topo.s['s1']

    info('*** [DEMO] convergenza STP (~35 s)\n')
    time.sleep(35)
    save(out, 'pingall', 'pingall: %.0f%% dropped' % net.pingAll())

    hsrv.cmd('iperf -s -p 5002 -i 1 > %s 2>&1 &' % os.path.join(out, 'u1_throughput.txt'))
    hsrv.cmd('iperf -s -u -p 5001 > /dev/null 2>&1 &')
    time.sleep(2)
    with open(os.path.join(out, 'u1_start'), 'w') as f:
        f.write('%.3f\n' % time.time())
    u1.cmd('iperf -c %s -p 5002 -t 150 > /dev/null 2>&1 &' % SRV)
    time.sleep(15)
    save(out, 'ping_prima_attacco', ping(u1, 'u1') + '\n' + ping(a1, 'a1'))

    info('*** [DEMO] flood di a1 (%s)\n' % flood)
    with open(os.path.join(out, 'flood_start'), 'w') as f:
        f.write('%.3f\n' % time.time())
    a1.cmd('iperf -c %s -u -p 5001 %s -t 60 > /dev/null 2>&1 &' % (SRV, FLOOD[flood]))

    if wait_block:
        for _ in range(60):
            if blocked(out):
                break
            time.sleep(1)
        time.sleep(3)
    else:
        time.sleep(25)

    save(out, 'ping_durante_attacco', ping(u1, 'u1') + '\n' + ping(a1, 'a1'))
    save(out, 'regola_drop', 'ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=100\n'
         + (s1.cmd('ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=100') or '(nessuna regola)\n'))
    time.sleep(20)
    net.stop()


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print('uso: sudo python3 experiments/demo_screens.py <cartella_output> <big|small> <0|1>')
        sys.exit(2)
    setLogLevel('info')
    main(sys.argv[1], sys.argv[2], sys.argv[3] == '1')
