#!/usr/bin/env python3
"""
Esecuzione automatica della campagna sperimentale.

Per ogni combinazione di scenario, livello di carico e ripetizione:
  1. avvia il controller Ryu con la modalita' corretta;
  2. costruisce la topologia importandola da topology.py;
  3. avvia i tre server iperf3 sul nodo srv;
  4. genera i tre flussi applicativi e la sonda ICMP;
  5. raccoglie latenze, perdite e statistiche delle code;
  6. smonta tutto e passa alla combinazione successiva.

La topologia non viene ridefinita qui ma si importa da topology.py

Uso:
    sudo python3 run_experiments.py
    sudo python3 run_experiments.py --ripetizioni 1     # prova rapida
"""

import argparse
import csv
import os
import re
import signal
import subprocess
import time

from mininet.log import setLogLevel
from mininet.clean import cleanup

import topology

#Parametri

SCENARI = ['slicing', 'none']
CARICHI_MBIT = [5, 10, 20]        # ritmo richiesto dal flusso bulk
RIPETIZIONI = 3

DURATA = 20                       # secondi di traffico per esecuzione
PING_INTERVALLO = 0.2             # un pacchetto ogni 200 ms
IP_SERVER = '10.0.0.100'

VIDEO_MBIT = 2
IOT_MBIT = 0.5

DIR_RISULTATI = 'risultati'

RE_RTT = re.compile(r'time=([\d.]+)\s*ms')
RE_PERDITA = re.compile(r'([\d.]+)% packet loss')


#Utilita'

def avvia_controller(modo, csv_path):
    """Lancia ryu-manager in un processo separato e attende che sia pronto."""
    env = dict(os.environ, SLICING_MODE=modo, SLICING_CSV=csv_path)
    proc = subprocess.Popen(
        ['ryu-manager', 'slicing_controller.py'],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid)
    time.sleep(3)                 # tempo di bind sulla porta 6653
    return proc


def ferma_controller(proc):
    """Termina l'intero gruppo di processi: ryu-manager genera figli."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass


def percentile(valori, p):
    if not valori:
        return float('nan')
    ordinati = sorted(valori)
    i = min(int(round(p * (len(ordinati) - 1))), len(ordinati) - 1)
    return ordinati[i]


def leggi_code(switch):
    """Restituisce {id_coda: (byte, pacchetti, errori)} dallo switch."""
    out = switch.cmd('ovs-ofctl -O OpenFlow13 queue-stats %s' % switch.name)
    code = {}
    for m in re.finditer(
            r'queue (\d+): bytes=(\d+), pkts=(\d+), errors=(\d+)', out):
        code[int(m.group(1))] = (int(m.group(2)), int(m.group(3)),
                                 int(m.group(4)))
    return code


# Singlona esecuzione

def esegui(scenario, carico, ripetizione, scrittore_rtt):
    etichetta = '%s / bulk %2d Mbps / rip %d' % (scenario, carico, ripetizione)
    print('  %s ...' % etichetta, end='', flush=True)

    csv_ctrl = os.path.join(
        DIR_RISULTATI, 'flussi_%s_%d_%d.csv' % (scenario, carico, ripetizione))

    ctrl = avvia_controller(scenario, csv_ctrl)
    net = None
    try:
        net = topology.costruisci(scenario)
        h1, h2, h3 = net.get('h1'), net.get('h2'), net.get('h3')
        srv, s1 = net.get('srv'), net.get('s1')

        # attesa che gli switch completino l'handshake con il controller
        time.sleep(2)

        for porta in (5004, 1883, 80):
            srv.cmd('iperf3 -s -p %d -D' % porta)
        time.sleep(1)

        # i tre flussi applicativi, tutti in background
        h3.cmd('iperf3 -c %s -p 80 -t %d -b %dM > /dev/null 2>&1 &'
               % (IP_SERVER, DURATA + 4, carico))
        h1.cmd('iperf3 -c %s -p 5004 -u -b %dM -t %d > /dev/null 2>&1 &'
               % (IP_SERVER, VIDEO_MBIT, DURATA + 4))
        h2.cmd('iperf3 -c %s -p 1883 -u -b %sM -t %d > /dev/null 2>&1 &'
               % (IP_SERVER, IOT_MBIT, DURATA + 4))

        time.sleep(2)             # i flussi entrano a regime

        # sonda di latenza: viaggia nella coda del video
        n_ping = int(DURATA / PING_INTERVALLO)
        uscita = h1.cmd('ping -c %d -i %s %s'
                        % (n_ping, PING_INTERVALLO, IP_SERVER))

        rtt = [float(x) for x in RE_RTT.findall(uscita)]
        m = RE_PERDITA.search(uscita)
        perdita = float(m.group(1)) if m else float('nan')

        code = leggi_code(s1)

        for i, v in enumerate(rtt):
            scrittore_rtt.writerow([scenario, carico, ripetizione, i, '%.3f' % v])

        riga = {
            'scenario': scenario,
            'carico_mbit': carico,
            'ripetizione': ripetizione,
            'rtt_medio': sum(rtt) / len(rtt) if rtt else float('nan'),
            'rtt_p95': percentile(rtt, 0.95),
            'rtt_max': max(rtt) if rtt else float('nan'),
            'perdita_pct': perdita,
            'scarti_coda0': code.get(0, (0, 0, 0))[2],
            'scarti_coda1': code.get(1, (0, 0, 0))[2],
            'scarti_coda2': code.get(2, (0, 0, 0))[2],
            'byte_coda0': code.get(0, (0, 0, 0))[0],
            'byte_coda1': code.get(1, (0, 0, 0))[0],
            'byte_coda2': code.get(2, (0, 0, 0))[0],
        }
        print('  RTT medio %7.1f ms   p95 %7.1f ms   perdita %.1f%%'
              % (riga['rtt_medio'], riga['rtt_p95'], riga['perdita_pct']))
        return riga

    finally:
        if net is not None:
            topology.pulisci_code(net.get('s1'))
            net.stop()
        ferma_controller(ctrl)
        cleanup()
        time.sleep(1)


# Main

def main():
    global DURATA

    p = argparse.ArgumentParser(description='Campagna sperimentale automatica')
    p.add_argument('--ripetizioni', type=int, default=RIPETIZIONI)
    p.add_argument('--durata', type=int, default=DURATA)
    args = p.parse_args()

    DURATA = args.durata

    if os.geteuid() != 0:
        raise SystemExit('Serve sudo: Mininet manipola il kernel.')

    os.makedirs(DIR_RISULTATI, exist_ok=True)
    setLogLevel('warning')        # la topologia altrimenti e' molto verbosa

    totale = len(SCENARI) * len(CARICHI_MBIT) * args.ripetizioni
    print('Campagna: %d esecuzioni da ~%d s ciascuna\n'
          % (totale, DURATA + 12))

    campi = ['scenario', 'carico_mbit', 'ripetizione', 'rtt_medio', 'rtt_p95',
             'rtt_max', 'perdita_pct', 'scarti_coda0', 'scarti_coda1',
             'scarti_coda2', 'byte_coda0', 'byte_coda1', 'byte_coda2']

    f_ril = open(os.path.join(DIR_RISULTATI, 'riepilogo.csv'), 'w')
    f_rtt = open(os.path.join(DIR_RISULTATI, 'campioni_rtt.csv'), 'w')
    ril = csv.DictWriter(f_ril, fieldnames=campi)
    ril.writeheader()
    rtt = csv.writer(f_rtt)
    rtt.writerow(['scenario', 'carico_mbit', 'ripetizione', 'seq', 'rtt_ms'])

    t0 = time.time()
    try:
        for scenario in SCENARI:
            print('Scenario: %s' % scenario)
            for carico in CARICHI_MBIT:
                for r in range(1, args.ripetizioni + 1):
                    riga = esegui(scenario, carico, r, rtt)
                    ril.writerow(riga)
                    f_ril.flush()
                    f_rtt.flush()
            print('')
    finally:
        f_ril.close()
        f_rtt.close()

    print('Completata in %.1f minuti.' % ((time.time() - t0) / 60.))
    print('Risultati in %s/' % DIR_RISULTATI)


if __name__ == '__main__':
    main()
