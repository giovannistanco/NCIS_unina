#!/usr/bin/env python3
"""
Generazione dei grafici a partire dai risultati della campagna.

Legge i file prodotti da run_experiments.py e produce tre figure:

  1. latenza_vs_carico.png   RTT medio e 95mo percentile al variare del carico
  2. distribuzione_rtt.png   distribuzione cumulata dei campioni a saturazione
  3. perdite.png             perdita del traffico protetto e scarti per coda

Uso:
    python3 plot.py
    python3 plot.py --dir risultati --out figure
"""

import argparse
import csv
import os
from collections import defaultdict

import matplotlib
matplotlib.use('Agg')             # nessun display disponibile sulla VM
import matplotlib.pyplot as plt

# ------------------------------------------------------------- estetica

C_SLICING = '#0F6E56'
C_BASE = '#D85A30'
C_GRIGLIA = '#C9C7BF'
C_TESTO = '#1F2430'

ETICHETTA = {'slicing': 'con slicing', 'none': 'senza slicing'}
COLORE = {'slicing': C_SLICING, 'none': C_BASE}

plt.rcParams.update({
    'font.size': 9,
    'axes.edgecolor': C_TESTO,
    'axes.labelcolor': C_TESTO,
    'text.color': C_TESTO,
    'xtick.color': C_TESTO,
    'ytick.color': C_TESTO,
    'axes.grid': True,
    'grid.color': C_GRIGLIA,
    'grid.linewidth': 0.5,
    'grid.alpha': 0.7,
    'figure.dpi': 130,
})


def stile(ax):
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.set_axisbelow(True)


# --------------------------------------------------------- lettura dati

def leggi_riepilogo(percorso):
    """{(scenario, carico): {metrica: [valori delle ripetizioni]}}"""
    dati = defaultdict(lambda: defaultdict(list))
    with open(percorso) as f:
        for r in csv.DictReader(f):
            k = (r['scenario'], int(r['carico_mbit']))
            for campo in ('rtt_medio', 'rtt_p95', 'rtt_max', 'perdita_pct',
                          'scarti_coda0', 'scarti_coda1', 'scarti_coda2'):
                dati[k][campo].append(float(r[campo]))
    return dati


def leggi_campioni(percorso):
    """{(scenario, carico): [rtt, ...]}"""
    dati = defaultdict(list)
    with open(percorso) as f:
        for r in csv.DictReader(f):
            dati[(r['scenario'], int(r['carico_mbit']))].append(
                float(r['rtt_ms']))
    return dati


def media(v):
    return sum(v) / len(v) if v else float('nan')


# ------------------------------------------------------------ figura 1

def fig_latenza(dati, carichi, out):
    fig, ax = plt.subplots(figsize=(6.4, 3.6))

    for sc in ('none', 'slicing'):
        medie = [media(dati[(sc, c)]['rtt_medio']) for c in carichi]
        p95 = [media(dati[(sc, c)]['rtt_p95']) for c in carichi]

        # barre di errore: minimo e massimo fra le ripetizioni
        lo = [medie[i] - min(dati[(sc, carichi[i])]['rtt_medio'])
              for i in range(len(carichi))]
        hi = [max(dati[(sc, carichi[i])]['rtt_medio']) - medie[i]
              for i in range(len(carichi))]

        ax.errorbar(carichi, medie, yerr=[lo, hi], color=COLORE[sc],
                    marker='o', markersize=5, linewidth=1.9, capsize=3,
                    label='%s, media' % ETICHETTA[sc])
        ax.plot(carichi, p95, color=COLORE[sc], marker='s', markersize=4,
                linewidth=1.1, linestyle='--', alpha=0.75,
                label='%s, 95%% percentile' % ETICHETTA[sc])

    ax.set_yscale('log')
    ax.set_xticks(carichi)
    ax.set_xticklabels(['%d' % c for c in carichi])
    ax.set_xlim(carichi[0] - 1.5, carichi[-1] + 1.5)
    ax.set_xlabel('ritmo richiesto dal flusso bulk (Mbps)')
    ax.set_ylabel('RTT della sonda (ms)')
    ax.set_title('Latenza del traffico protetto al variare del carico',
                 fontsize=10, fontweight='bold', pad=10)

    # soglia di saturazione: bulk + video + iot = capacita' del collo di bottiglia
    ax.axvline(7.5, color=C_TESTO, linewidth=0.8, linestyle=':', alpha=0.6)
    ax.annotate('saturazione del\ncollegamento', xy=(7.5, 30),
                xytext=(8.2, 26), fontsize=7, alpha=0.75, va='center')

    ax.legend(frameon=False, fontsize=7.5, loc='center right')
    stile(ax)
    fig.tight_layout()
    fig.savefig(os.path.join(out, 'latenza_vs_carico.png'))
    plt.close(fig)


# ------------------------------------------------------------ figura 2

def fig_distribuzione(campioni, carico, out):
    fig, ax = plt.subplots(figsize=(6.4, 3.4))

    for sc in ('slicing', 'none'):
        v = sorted(campioni[(sc, carico)])
        if not v:
            continue
        y = [100.0 * (i + 1) / len(v) for i in range(len(v))]
        ax.plot(v, y, color=COLORE[sc], linewidth=2, label=ETICHETTA[sc])

    ax.set_xscale('log')
    ax.set_xlabel('RTT (ms)')
    ax.set_ylabel('percentuale di pacchetti (%)')
    ax.set_ylim(0, 100)
    ax.set_title('Distribuzione cumulata del RTT a saturazione '
                 '(bulk a %d Mbps)' % carico,
                 fontsize=10, fontweight='bold', pad=10)
    ax.legend(frameon=False, fontsize=8, loc='center right')
    stile(ax)
    fig.tight_layout()
    fig.savefig(os.path.join(out, 'distribuzione_rtt.png'))
    plt.close(fig)


# ------------------------------------------------------------ figura 3

def fig_perdite(dati, carichi, out):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.6, 3.3))

    larghezza = 0.36
    x = range(len(carichi))

    # pannello sinistro: perdita subita dal traffico protetto
    for k, sc in enumerate(('slicing', 'none')):
        v = [media(dati[(sc, c)]['perdita_pct']) for c in carichi]
        pos = [i + (k - 0.5) * larghezza for i in x]
        ax1.bar(pos, v, larghezza, color=COLORE[sc], label=ETICHETTA[sc])
        # etichetta esplicita: senza, le barre a zero sembrano dati mancanti
        for p, val in zip(pos, v):
            ax1.text(p, val + 0.18, '%.1f%%' % val, ha='center',
                     fontsize=7, fontweight='bold', color=COLORE[sc])

    ax1.set_xticks(list(x))
    ax1.set_xticklabels(['%d Mbps' % c for c in carichi])
    ax1.set_ylabel('perdita della sonda (%)')
    ax1.set_ylim(0, 8.6)
    ax1.set_title('Perdita subita dal traffico protetto',
                  fontsize=9.5, fontweight='bold', pad=8)
    ax1.legend(frameon=False, fontsize=7.5, loc='upper left')
    stile(ax1)

    # pannello destro: dove cadono gli scarti, nei due scenari
    c_sat = carichi[-1]
    nomi = ['coda 0\nbulk', 'coda 1\nvideo', 'coda 2\nIoT', 'coda unica\n(baseline)']
    valori = [media(dati[('slicing', c_sat)][campo])
              for campo in ('scarti_coda0', 'scarti_coda1', 'scarti_coda2')]
    valori.append(media(dati[('none', c_sat)]['scarti_coda0']))
    colori = [C_SLICING, C_SLICING, C_SLICING, C_BASE]

    ax2.bar(nomi, valori, color=colori, width=0.6)
    for i, v in enumerate(valori):
        ax2.text(i, v + max(valori) * 0.035, '%.0f' % v,
                 ha='center', fontsize=8, fontweight='bold')

    ax2.set_ylabel('pacchetti scartati')
    ax2.set_title('Dove cadono gli scarti (bulk a %d Mbps)' % c_sat,
                  fontsize=9.5, fontweight='bold', pad=8)
    ax2.set_ylim(0, max(valori) * 1.22 if max(valori) else 1)
    ax2.tick_params(axis='x', labelsize=7.5)
    stile(ax2)

    fig.tight_layout()
    fig.savefig(os.path.join(out, 'perdite.png'))
    plt.close(fig)


# ------------------------------------------------------------------ main

def main():
    p = argparse.ArgumentParser(description='Grafici della campagna')
    p.add_argument('--dir', default='risultati')
    p.add_argument('--out', default='figure')
    args = p.parse_args()

    os.makedirs(args.out, exist_ok=True)

    dati = leggi_riepilogo(os.path.join(args.dir, 'riepilogo.csv'))
    campioni = leggi_campioni(os.path.join(args.dir, 'campioni_rtt.csv'))

    carichi = sorted({c for (_, c) in dati})
    print('Carichi rilevati: %s' % carichi)

    fig_latenza(dati, carichi, args.out)
    fig_distribuzione(campioni, carichi[1], args.out)
    fig_perdite(dati, carichi, args.out)

    print('Figure scritte in %s/' % args.out)
    for f in sorted(os.listdir(args.out)):
        print('   %s' % f)


if __name__ == '__main__':
    main()
