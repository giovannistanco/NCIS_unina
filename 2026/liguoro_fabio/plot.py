#!/usr/bin/python3
import sys
import csv

import matplotlib
matplotlib.use('Agg')          # backend non interattivo: salva su file
import matplotlib.pyplot as plt

CSV_PATH = sys.argv[1] if len(sys.argv) > 1 else '/tmp/te_monitor.csv'
OUT_PATH = sys.argv[2] if len(sys.argv) > 2 else 'risultati.png'

# Devono coincidere con i valori impostati nel controller
THRESHOLD_HIGH = 0.80
THRESHOLD_LOW = 0.30
LINK_CAPACITY_MBPS = 10.0


def load(path):
    t, primary, secondary, total, state = [], [], [], [], []
    with open(path) as f:
        for row in csv.DictReader(f):
            t.append(float(row['t']))
            primary.append(float(row['thr_primary_mbps']))
            secondary.append(float(row['thr_secondary_mbps']))
            total.append(float(row['thr_total_mbps']))
            state.append(row['state'])

    if not t:
        return t, primary, secondary, total, state

    # Individua il primo campione con traffico apprezzabile (> 0.05 Mbps)
    origin = t[0]
    for i, tot in enumerate(total):
        if tot > 0.05:
            origin = t[i]
            break

    t = [x - origin for x in t]
    return t, primary, secondary, total, state


def find_transitions(t, state):
    transitions = []
    for i in range(1, len(state)):
        if state[i] != state[i - 1]:
            transitions.append((t[i], state[i]))
    return transitions


def main():
    t, primary, secondary, total, state = load(CSV_PATH)
    if not t:
        print('Nessun dato in %s' % CSV_PATH)
        return

    transitions = find_transitions(t, state)

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 7), sharex=True)

    # Riquadro superiore: throughput sui due percorsi
    ax1.plot(t, primary, label='Percorso primario (s1-s2-s4)',
             linewidth=2)
    ax1.plot(t, secondary, label='Percorso secondario (s1-s3-s4)',
             linewidth=2, linestyle='--')
    ax1.axhline(LINK_CAPACITY_MBPS, color='gray', linestyle=':',
                label='Capacita\' del link (10 Mbps)')
    ax1.set_ylabel('Throughput [Mbps]')
    ax1.set_title('Traffic Engineering adattivo in SDN: '
                  'occupazione dei due percorsi')
    ax1.legend(loc='upper left', fontsize=9)
    ax1.grid(alpha=0.3)

    # Riquadro inferiore: utilizzo aggregato e soglie
    utilization = [tot / LINK_CAPACITY_MBPS for tot in total]
    ax2.plot(t, utilization, color='black', linewidth=2,
             label='Utilizzo aggregato U')
    ax2.axhline(THRESHOLD_HIGH, color='red', linestyle='--',
                label='Soglia alta (0.80)')
    ax2.axhline(THRESHOLD_LOW, color='green', linestyle='--',
                label='Soglia bassa (0.30)')
    # La banda morta fra le due soglie e' cio' che impedisce il flapping
    ax2.axhspan(THRESHOLD_LOW, THRESHOLD_HIGH, color='yellow', alpha=0.12)
    ax2.set_ylabel('Utilizzo U')
    ax2.set_xlabel('Tempo [s]')
    ax2.legend(loc='upper left', fontsize=9)
    ax2.grid(alpha=0.3)

    # Marcatori verticali sugli istanti di rerouting
    for t_change, new_state in transitions:
        for ax in (ax1, ax2):
            ax.axvline(t_change, color='purple', linestyle='-', alpha=0.6)
        ax1.annotate('FlowMod\n-> %s' % new_state,
                     xy=(t_change, LINK_CAPACITY_MBPS * 0.6),
                     fontsize=8, color='purple',
                     ha='center' if t_change > 10 else 'left')

    plt.tight_layout()
    plt.savefig(OUT_PATH, dpi=150)
    print('Grafico salvato in %s' % OUT_PATH)
    print('Transizioni di stato rilevate: %s' % transitions)


if __name__ == '__main__':
    main()
