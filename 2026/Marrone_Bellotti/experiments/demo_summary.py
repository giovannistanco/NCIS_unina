#!/usr/bin/python3
"""Riepilogo di una casistica della demo, pronto da fotografare.

Uso: python3 experiments/demo_summary.py <cartella_casistica> "<titolo>"
"""
import os
import re
import sys

LINE = re.compile(r'(\d+\.\d+)-\s*(\d+\.\d+)\s+sec.*?([\d.]+)\s+([KMG]?)bits/sec')
SCALE = {'': 1e-6, 'K': 1e-3, 'M': 1.0, 'G': 1e3}


def read(d, name):
    p = os.path.join(d, name)
    return open(p).read() if os.path.exists(p) else ''


def throughput(d):
    """{secondo di fine intervallo, relativo all'avvio del download di u1: Mbps}"""
    out = {}
    for line in read(d, 'u1_throughput.txt').splitlines():
        m = LINE.search(line)
        if m and float(m.group(2)) - float(m.group(1)) <= 1.5:
            out[float(m.group(2))] = float(m.group(3)) * SCALE[m.group(4)]
    return out


def avg(tp, lo, hi):
    v = [x for t, x in tp.items() if lo < t <= hi]
    return sum(v) / len(v) if v else float('nan')


def main(d, title):
    t_u1 = float(read(d, 'u1_start') or 0)
    t_fl = float(read(d, 'flood_start') or 0)
    off = t_fl - t_u1                                  # inizio flood nel tempo di iperf
    ev = [l.split(',') for l in read(d, 'eventi.csv').splitlines() if l.count(',') >= 2]
    det = next((float(e[0]) - t_fl for e in ev if e[1] == 'DETECT'), None)
    blk = next((float(e[0]) - t_fl for e in ev if e[1] == 'BLOCK'), None)
    blocked_macs = sorted({e[2] for e in ev if e[1] == 'BLOCK'})
    tp = throughput(d)

    print('=' * 70)
    print(title)
    print('=' * 70)
    for l in read(d, 'controller.txt').splitlines()[:8]:
        print(l)
    print('-' * 70)
    print('primo DETECT: %s   BLOCK: %s   MAC bloccati: %s' % (
        '+%.1f s' % det if det is not None else 'mai',
        '+%.1f s' % blk if blk is not None else 'mai',
        ', '.join(blocked_macs) or 'nessuno'))
    print('throughput u1: prima %.1f Mbps | primi 10 s di flood %.1f Mbps | da +20 a +40 s %.1f Mbps'
          % (avg(tp, off - 10, off), avg(tp, off, off + 10), avg(tp, off + 20, off + 40)))
    print('-' * 70)
    for l in read(d, 'ping_durante_attacco.txt').splitlines():
        if l.startswith('mininet>') or 'packet loss' in l:
            print(l)
    print('-' * 70)
    print(read(d, 'regola_drop.txt').rstrip())
    print()


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
