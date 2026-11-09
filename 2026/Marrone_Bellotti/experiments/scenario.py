#!/usr/bin/python3
"""Scenario di esperimento DoS riproducibile (Fase 4).

Genera lo stesso traffico in tutti i casi; cambia solo il controller avviato a parte:
  - SENZA mitigazione:   PYTHONPATH=. MITIGATE=0 ryu-manager controller.py
  - CON  mitigazione:    PYTHONPATH=. ryu-manager controller.py
  - SENZA whitelist:     PYTHONPATH=. WHITELIST=0 ryu-manager controller.py
    (misura i falsi positivi del detector: se u1 viene bloccato compare nel log eventi)

Traffico (host u1 e a1 sono sullo STESSO switch s1 -> caso "piracy shield"):
  - hsrv: server iperf TCP (porta 5002, report per-secondo LATO SERVER) + UDP (5001)
  - u1  : client TCP legittimo verso hsrv per 100s, log per-secondo (-i 1)
  - a1  : attaccante. Fase BASELINE (0.5 Mbps UDP, 0-40s) per far apprendere la
          baseline al detector, poi FLOOD (25 Mbps UDP, 40-100s) che satura
          l'uplink condiviso s1-s2 (il collo di bottiglia effettivo per u1) e
          degrada u1. Lo spike e' cio' che il detector adattivo rileva.
  - a2  : (solo con --both) stesso profilo di a1, da s5: attacco distribuito.

Con --cold il flood parte "a freddo" a t=0, senza fase di baseline: un detector che
confronta il flusso con la propria storia impara il flood come normale.

File prodotti accanto a <u1_tcp_log_path>:
  - <log>               throughput di u1 misurato dal client iperf
  - <log>.srv           throughput ricevuto da hsrv (non puo' superare il link: e'
                        la misura da usare per il grafico)
  - <log>.flood_start   epoch dell'inizio del flood (per il tempo di rilevamento,
                        da confrontare con EVENT_LOG del controller)

Uso:  sudo python3 experiments/scenario.py <u1_tcp_log_path> [--both] [--cold] [--syn|--synbig]
"""
import sys
import time

from mininet.log import setLogLevel, info

sys.path.insert(0, '.')
from topology import DoSTopo  # noqa: E402

BASELINE_S = 40               # durata della fase di baseline di a1 (0 con --cold)
FLOOD_S = 60


# Flood verso un servizio che risponde: SYN alla porta TCP di iperf su hsrv, che risponde
# con un SYN-ACK a ogni SYN (a1 riceve traffico di ritorno, il tetto sui byte/s non scatta).
#   syn     SYN da 60 B al massimo rate (molti pps)
#   synbig  SYN con 1400 B di payload a ~830 pps (~1.2 MB/s, sotto il tetto sui pps)
FLOODS = {
    'udp': 'iperf -c 10.0.0.100 -u -p 5001 -b 25M -t %d' % FLOOD_S,
    'syn': 'timeout %d hping3 -q -S -p 5002 --flood 10.0.0.100' % FLOOD_S,
    'synbig': 'timeout %d hping3 -q -S -p 5002 -d 1400 -i u1200 10.0.0.100' % FLOOD_S,
}


def attack_cmd(meta, cold=False, kind='udp'):
    """Baseline 0.5 Mbps, poi timestamp di inizio flood, poi flood (default UDP 25 Mbps)."""
    flood = 'date +%%s.%%N > %s; %s' % (meta, FLOODS[kind])
    if cold:
        return '(%s) > /dev/null 2>&1 &' % flood
    return ('(iperf -c 10.0.0.100 -u -p 5001 -b 0.5M -t %d; %s) > /dev/null 2>&1 &'
            % (BASELINE_S, flood))


def main(u1_log, both=False, cold=False, kind='udp'):
    topo = DoSTopo()
    net = topo.net
    hsrv, u1, a1, a2 = topo.h_srv, topo.u1, topo.a1, topo.a2
    total = FLOOD_S + (0 if cold else BASELINE_S)

    info("*** [SCN] Attendo convergenza STP (~35s)\n")
    time.sleep(35)
    info("*** [SCN] pingall di warm-up (popola L2/ARP)\n")
    net.pingAll()

    info("*** [SCN] Avvio server iperf su hsrv (TCP 5002, UDP 5001)\n")
    hsrv.cmd('iperf -s -p 5002 -i 1 > %s.srv 2>&1 &' % u1_log)
    hsrv.cmd('iperf -s -u -p 5001 > /tmp/srv_udp.log 2>&1 &')
    time.sleep(2)

    info("*** [SCN] u1: transfer TCP legittimo %ds (log per-secondo)\n" % total)
    u1.cmd('iperf -c 10.0.0.100 -p 5002 -t %d -i 1 > %s 2>&1 &' % (total, u1_log))

    if cold:
        info("*** [SCN] a1: FLOOD %s a freddo da t=0 (%ds)\n" % (kind, FLOOD_S))
    else:
        info("*** [SCN] a1: baseline 0.5Mbps (%ds) poi FLOOD %s (%ds)\n"
             % (BASELINE_S, kind, FLOOD_S))
    a1.cmd(attack_cmd(u1_log + '.flood_start', cold, kind))
    if both:
        info("*** [SCN] a2: stesso profilo di a1 (attacco distribuito)\n")
        a2.cmd(attack_cmd(u1_log + '.flood_start_a2', cold, kind))

    info("*** [SCN] Attendo la fine del transfer di u1 (~%ds)\n" % (total + 5))
    time.sleep(total + 5)

    info("*** [SCN] Fine scenario. Log u1 -> %s\n" % u1_log)
    net.stop()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("uso: sudo python3 experiments/scenario.py <u1_tcp_log_path> [--both] [--cold] "
              "[--syn|--synbig]")
        sys.exit(2)
    setLogLevel('info')
    kind = 'syn' if '--syn' in sys.argv else 'synbig' if '--synbig' in sys.argv else 'udp'
    main(sys.argv[1], both='--both' in sys.argv, cold='--cold' in sys.argv, kind=kind)
