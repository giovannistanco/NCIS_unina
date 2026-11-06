import argparse
import json
import os
import time

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel

SERVER = '10.0.0.5'
ATTACKERS = {'baseline': [], 'single': ['h2'], 'ddos': ['h2', 'h4']}
PING_INTERVAL = 0.5


def build():
    net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    net.addController('c0', ip='127.0.0.1', port=6653)
    s1, s2, s3, s4 = [net.addSwitch('s%d' % i, protocols='OpenFlow13') for i in range(1, 5)]
    h = {n: net.addHost(n, ip='10.0.0.%d/24' % i) for i, n in enumerate(['h1', 'h2', 'h3', 'h4', 'h5'], 1)}
    
    # definizione della topologia identica a quella di topo.py
    net.addLink(h['h1'], s1, bw=100)
    net.addLink(h['h2'], s1, bw=100)
    net.addLink(h['h3'], s2, bw=100)
    net.addLink(h['h4'], s2, bw=100)
    net.addLink(s1, s3, bw=50)
    net.addLink(s2, s3, bw=50)
    net.addLink(s3, s4, bw=20)
    net.addLink(s4, h['h5'], bw=100)
    return net


def run_phase(net, kind, outdir, attackers, t_pre, t_att, t_post):
    h1 = net.get('h1')
    total = t_pre + t_att + t_post
    probe = os.path.join(outdir, kind + '.txt')
    t_start = time.time()
    if kind == 'iperf':
        h1.cmd('iperf -c %s -t %d -i 1 > %s 2>&1 &' % (SERVER, total, probe))
    else:
        h1.cmd('ping -D -i %s -c %d %s > %s 2>&1 &' % (PING_INTERVAL, int(total / PING_INTERVAL), SERVER, probe))
    time.sleep(t_pre)
    t_att_start = time.time()
    for a in attackers:
        out = os.path.join(outdir, 'attack_%s_%s.txt' % (kind, a))
        net.get(a).cmd('iperf -u -c %s -b 100M -t %d > %s 2>&1 &' % (SERVER, t_att, out))
    time.sleep(t_att)
    t_att_end = time.time()
    time.sleep(max(0.0, total - (time.time() - t_start)) + 3)   # attende la fine della sonda
    return {'start': t_start, 'attack_start': t_att_start, 'attack_end': t_att_end, 'attackers': attackers}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--label', choices=['off', 'on'], required=True, help='stato di PROTECTION nel controller (solo per nominare le cartelle)')
    ap.add_argument('--scenario', choices=list(ATTACKERS), required=True)
    ap.add_argument('--reps', type=int, default=3)
    ap.add_argument('--out', default=os.path.expanduser('~/Documents/NCIS/results'))
    ap.add_argument('--t-pre', type=int, default=8)
    ap.add_argument('--t-att', type=int, default=20)
    ap.add_argument('--t-post', type=int, default=12)
    ap.add_argument('--cooldown', type=int, default=None,
                    help='pausa tra le fasi/ripetizioni; default 15 s (off) o 140 s (on con attacco, serve al decadimento della penalita)')
    args = ap.parse_args()

    attackers = ATTACKERS[args.scenario]
    cool = args.cooldown if args.cooldown is not None else (140 if (args.label == 'on' and attackers) else 15)

    setLogLevel('warning')
    net = build()
    net.start()
    net.waitConnected()
    net.get('h5').cmd('iperf -s > /dev/null 2>&1 &')
    net.get('h5').cmd('iperf -s -u > /dev/null 2>&1 &')
    time.sleep(1)
    net.pingAll()   # fa imparare i binding ARP (TOFU) PRIMA di qualunque attacco

    base = os.path.join(args.out, '%s_%s' % (args.label, args.scenario))
    for rep in range(1, args.reps + 1):
        outdir = os.path.join(base, 'rep%d' % rep)
        os.makedirs(outdir, exist_ok=True)
        print('== %s_%s rep %d/%d ==' % (args.label, args.scenario, rep, args.reps), flush=True)
        meta = {'label': args.label, 'scenario': args.scenario,
                't_pre': args.t_pre, 't_att': args.t_att, 't_post': args.t_post,
                'ping_interval': PING_INTERVAL}
        meta['iperf'] = run_phase(net, 'iperf', outdir, attackers, args.t_pre, args.t_att, args.t_post)
        time.sleep(cool)
        meta['ping'] = run_phase(net, 'ping', outdir, attackers, args.t_pre, args.t_att, args.t_post)
        with open(os.path.join(outdir, 'meta.json'), 'w') as f:
            json.dump(meta, f, indent=1)
        if rep < args.reps:
            time.sleep(cool)
    net.stop()
    print('Fatto. Risultati in', base)


if __name__ == '__main__':
    main()