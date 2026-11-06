#!/usr/bin/python3
"""Generatore del dataset ML: una sessione Mininet, N episodi con parametri casuali.

Il controller va avviato a parte con MITIGATE=0 e FEATURE_LOG=<log.csv> (lo fa
experiments/gen_dataset.sh). Per ogni episodio (60 s + 5 s di pausa):

  benigno  u1 e u2 scelgono 1-2 profili tra:
             tcp  iperf TCP a 1/3/5/8 Mbps
             udp  iperf UDP legittimo 1-8 Mbps, pacchetti 400-1470 B
             ping ping rapido (5-200 ms) a pacchetti piccoli/medi
             voip UDP piccolo tipo VoIP/DNS: 64-512 kbit/s, 60-200 B
             http loop di curl verso un http.server (file da 20 kB o 2 MB)
           cosi' il benigno si sovrappone all'attacco per pps, bps e dimensione.
  attacco  famiglia (udp | syn | icmp | lowrate) con hping3, payload 0-1400 B,
           rate variabile (anche --flood), da a1, a2 o entrambi (a rotazione).
           Parte tra 15 e 25 s e dura 20-30 s; PRIMA e DOPO l'attaccante genera
           traffico benigno leggero, etichettato come benigno (finestra temporale).
  benign   circa un episodio su cinque e' solo benigno (nessun attacco).

Ogni episodio e' scritto in <meta.jsonl>: t0, t1, family, attackers (MAC),
atk_start, atk_end, params. ml/extract_features.py lo usa per etichettare.

Uso: python3 experiments/gen_dataset.py <meta.jsonl> [--families udp,syn,icmp,lowrate]
                                        [--per-family 5] [--seed 1]
"""
import argparse
import json
import random
import sys
import time

from mininet.log import setLogLevel, info

sys.path.insert(0, '.')
from topology import DoSTopo  # noqa: E402

SRV = '10.0.0.100'
EPISODE_S = 60
GAP_S = 5
MACS = {'a1': '00:00:00:00:00:f1', 'a2': '00:00:00:00:00:f2'}


def benign_cmd(rng, kind, dur):
    if kind == 'tcp':
        return 'iperf -c %s -p 5002 -b %dM -t %d' % (SRV, rng.choice([1, 3, 5, 8]), dur)
    if kind == 'udp':
        return 'iperf -c %s -u -p 5003 -b %dM -l %d -t %d' % (
            SRV, rng.randint(1, 8), rng.randint(400, 1470), dur)
    if kind == 'ping':
        return 'ping -q -i %s -s %d -w %d %s' % (
            rng.choice(['0.005', '0.01', '0.05', '0.2']), rng.randint(56, 1000), dur, SRV)
    if kind == 'voip':
        return 'iperf -c %s -u -p 5003 -b %dK -l %d -t %d' % (
            SRV, rng.choice([64, 128, 256, 512]), rng.randint(60, 200), dur)
    if kind == 'http':
        return ("timeout %d sh -c 'while true; do curl -s -o /dev/null http://%s:8000/%s; "
                "sleep %s; done'" % (dur, SRV, rng.choice(['small.bin', 'big.bin']),
                                      rng.choice(['0.05', '0.2', '1'])))
    raise ValueError(kind)


def attack_cmd(rng, family, dur):
    """Ritorna (comando, parametri)."""
    payload = rng.randint(0, 1400)
    if family == 'lowrate':
        iv = rng.choice([5000, 10000, 20000])          # 50-200 pps
    else:
        iv = rng.choice(['flood', 100, 200, 400, 1000, 2500])
    rate = '--flood' if iv == 'flood' else '-i u%d' % iv
    proto = {'udp': '--udp -p 5001', 'lowrate': '--udp -p 5001',
             'syn': '-S -p 80', 'icmp': '--icmp'}[family]
    if family == 'syn':
        payload = rng.randint(0, 200)
    cmd = 'timeout %d hping3 %s %s -d %d -q %s' % (dur, proto, rate, payload, SRV)
    return cmd, {'payload': payload, 'interval_us': iv}


def bg(host, cmd):
    host.cmd('(%s) > /dev/null 2>&1 &' % cmd)


def plan(families, per_family):
    """Lista di episodi: (famiglia|None, attaccanti). Gli attaccanti ruotano tra
    a1, a2 ed entrambi; circa un episodio su cinque e' solo benigno."""
    combos = [['a1'], ['a2'], ['a1', 'a2']]
    eps = [(f, combos[i % 3]) for f in families for i in range(per_family)]
    eps += [(None, [])] * max(1, len(eps) // 4)
    return eps


def main(meta_path, families, per_family, seed):
    topo = DoSTopo()
    net = topo.net
    hosts = {'u1': topo.u1, 'u2': topo.u2, 'a1': topo.a1, 'a2': topo.a2}
    hsrv = topo.h_srv
    info("*** [GEN] convergenza STP (~35s)\n")
    time.sleep(35)
    net.pingAll()
    hsrv.cmd('iperf -s -p 5002 > /dev/null 2>&1 &')
    hsrv.cmd('iperf -s -u -p 5001 > /dev/null 2>&1 &')
    hsrv.cmd('iperf -s -u -p 5003 > /dev/null 2>&1 &')
    hsrv.cmd('mkdir -p /tmp/www && cd /tmp/www && head -c 20000 /dev/urandom > small.bin'
             ' && head -c 2000000 /dev/urandom > big.bin'
             ' && (python3 -m http.server 8000 > /dev/null 2>&1 &) ; cd - > /dev/null')
    time.sleep(2)

    episodes = plan(families, per_family)
    random.Random(seed).shuffle(episodes)
    with open(meta_path, 'a') as meta:
        for i, (family, attackers) in enumerate(episodes):
            rng = random.Random(seed * 1000 + i)
            t0 = time.time()
            prof = {}
            for name in ('u1', 'u2'):
                prof[name] = rng.sample(['tcp', 'udp', 'ping', 'voip', 'http'], rng.randint(1, 2))
                for kind in prof[name]:
                    bg(hosts[name], benign_cmd(rng, kind, EPISODE_S))
            for name in ('a1', 'a2'):                # traffico benigno leggero degli attaccanti
                prof[name] = [rng.choice(['ping', 'http', 'voip'])]
                bg(hosts[name], benign_cmd(rng, prof[name][0], EPISODE_S))
            rec = {'episode': i, 't0': t0, 't1': t0 + EPISODE_S, 'family': family or 'benign',
                   'attackers': [], 'atk_start': 0.0, 'atk_end': 0.0, 'benign_profiles': prof}
            if family:
                off, dur = rng.uniform(15, 25), rng.randint(20, 30)
                time.sleep(max(0.0, t0 + off - time.time()))
                cmd, params = attack_cmd(rng, family, dur)
                rec.update(atk_start=time.time(), atk_end=time.time() + dur, params=params,
                           attackers=[MACS[a] for a in attackers], cmd=cmd)
                for a in attackers:
                    bg(hosts[a], cmd)
            info("*** [GEN] episodio %d/%d: %s da %s\n" % (
                i + 1, len(episodes), family or 'solo benigno', '+'.join(attackers) or '-'))
            time.sleep(max(0.0, t0 + EPISODE_S + GAP_S - time.time()))
            meta.write(json.dumps(rec) + '\n')
            meta.flush()
    net.stop()


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('meta')
    ap.add_argument('--families', default='udp,syn,icmp,lowrate')
    ap.add_argument('--per-family', type=int, default=5)
    ap.add_argument('--seed', type=int, default=1)
    a = ap.parse_args()
    setLogLevel('info')
    main(a.meta, a.families.split(','), a.per_family, a.seed)
