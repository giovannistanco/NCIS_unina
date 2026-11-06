#!/usr/bin/python3
"""Generazione traffico per il MLDetector (Fase 5).

Per ottenere un dataset con DUE classi ATTIVE e ben separate, la raccolta si fa in
due run distinti (il flood starverebbe il TCP legittimo se concorrente):

  benign : solo u1,u2 -> TCP normale 3 Mbps (pacchetti grandi, ~250 pps)  [label 0]
  attack : solo a1,a2 -> UDP packet-flood 5 Mbps, pacchetti 250B (~2500 pps) [label 1]
           pattern realistico di DoS: alto pps a parita' di banda.
  lowrate: solo a1,a2 -> UDP flood low-rate 1 Mbps, pacchetti 250B (~500 pps,
           ~125 kB/s: sotto la soglia assoluta su bps del detector adattivo) [label 1]
           da usare come test set separato (attacco mai visto in training).
  both   : tutti insieme + mitigazione (demo end-to-end del MLDetector)

Per avere piu' run (e uno split per run in train.py) basta ripetere la raccolta con
un FEATURE_LOG diverso per ogni run.

Uso:  sudo python3 experiments/scenario_ml.py <benign|attack|lowrate|both> [durata_s]
Con un controller avviato a parte (MITIGATE=0 + FEATURE_LOG per le raccolte).
"""
import sys
import time

from mininet.log import setLogLevel, info

sys.path.insert(0, '.')
from topology import DoSTopo  # noqa: E402


def main(mode, dur):
    topo = DoSTopo()
    net = topo.net
    hsrv, u1, u2, a1, a2 = topo.h_srv, topo.u1, topo.u2, topo.a1, topo.a2

    info("*** [ML:%s] convergenza STP (~35s)\n" % mode)
    time.sleep(35)
    net.pingAll()
    hsrv.cmd('iperf -s -p 5002 > /tmp/srv_tcp.log 2>&1 &')
    hsrv.cmd('iperf -s -u -p 5001 > /tmp/srv_udp.log 2>&1 &')
    time.sleep(2)

    if mode in ('benign', 'both'):
        info("*** [ML:%s] benigno: u1,u2 TCP 3 Mbps (%ds)\n" % (mode, dur))
        u1.cmd('iperf -c 10.0.0.100 -p 5002 -b 3M -t %d > /tmp/u1.log 2>&1 &' % dur)
        u2.cmd('iperf -c 10.0.0.100 -p 5002 -b 3M -t %d > /tmp/u2.log 2>&1 &' % dur)

    if mode in ('attack', 'both'):
        info("*** [ML:%s] attacco: a1,a2 UDP packet-flood 5 Mbps 250B (%ds)\n" % (mode, dur))
        a1.cmd('iperf -c 10.0.0.100 -u -p 5001 -b 5M -l 250 -t %d > /tmp/a1.log 2>&1 &' % dur)
        a2.cmd('iperf -c 10.0.0.100 -u -p 5001 -b 5M -l 250 -t %d > /tmp/a2.log 2>&1 &' % dur)

    if mode == 'lowrate':
        info("*** [ML:%s] attacco low-rate: a1,a2 UDP 1 Mbps 250B (%ds)\n" % (mode, dur))
        a1.cmd('iperf -c 10.0.0.100 -u -p 5001 -b 1M -l 250 -t %d > /tmp/a1.log 2>&1 &' % dur)
        a2.cmd('iperf -c 10.0.0.100 -u -p 5001 -b 1M -l 250 -t %d > /tmp/a2.log 2>&1 &' % dur)

    info("*** [ML:%s] in corso (~%ds)\n" % (mode, dur + 5))
    time.sleep(dur + 5)
    # conserva i log dei singoli host come evidenza della run
    for h in ('u1', 'u2', 'a1', 'a2'):
        u1.cmd('cp /tmp/%s.log experiments/ml_%s_%s.log 2>/dev/null' % (h, mode, h))
    net.stop()


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'both'
    dur = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    setLogLevel('info')
    main(mode, dur)
