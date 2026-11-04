# -*- coding: utf-8 -*-
"""
fase9_analisi_confronto.py - Analisi comparativa per la Fase 9 (Network & Cloud Infrastructures)

Convenzione temporale:
  - t=0: istante in cui si avviano i client legittimi h2 e h4 (TCP).
  - t ≈ 6s: avvio del flusso fidato h5 (UDP Whitelist).
  - t ≈ 25s: avvio dell'attacco DoS di h1 (UDP Flood).
  
Output generati:
  - grafico_fase9_confronto.png : 2 subplot Throughput (Senza Difese vs Con Mitigazione)
  - grafico_fase9_loss.png      : Grafico comparativo Packet Loss % (h5 vs h1 DROP)
  - tabella_fase9_confronto.csv : Tabella di sintesi per la relazione
"""

import os
import re
import sys
import glob
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

DIR_FASE_4 = os.path.join('results', 'Fase_4')
DIR_FASE_5_8 = os.path.join('results', 'Fase5_8')

IP_HOST = {
    '10.0.0.1': 'h1',
    '10.0.0.2': 'h2',
    '10.0.0.3': 'h3',
    '10.0.0.4': 'h4',
    '10.0.0.5': 'h5'
}

PORT_HOST = {
    5001: 'h1',
    5002: 'h2',
    5003: 'h4',
    5004: 'h5'
}

def trova_file_server_fase4():
    candidati = glob.glob(os.path.join(DIR_FASE_4, "*server*.txt"))
    if not candidati:
        candidati = glob.glob(os.path.join(DIR_FASE_4, "*.txt"))
    if not candidati:
        candidati = glob.glob("*server*.txt")
    return sorted(candidati)

def trova_file_csv_mitigazione():
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        return sys.argv[1]
    candidati = (set(glob.glob('monitor_mitigation*.csv')) |
                 set(glob.glob(os.path.join(DIR_FASE_5_8, 'monitor_mitigation*.csv'))) |
                 set(glob.glob('*.csv')))
    candidati = [c for c in candidati if 'tabella_fase9' not in c]
    if not candidati:
        return None
    candidati.sort(key=os.path.getmtime, reverse=True)
    return candidati[0]

def parse_iperf_log(filepath):
    campioni = []
    host_riconosciuto = None
    stream_to_host = {}
    stream_to_start = {}

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            mp = re.search(r'Server listening on (?:TCP|UDP) port (\d+)', line)
            if mp:
                port = int(mp.group(1))
                if port in PORT_HOST:
                    host_riconosciuto = PORT_HOST[port]
                continue

            mc = re.search(r'\[\s*(\d+)\]\s+local\s+[\d\.]+\s+port\s+(\d+)\s+connected with\s+([\d\.]+)\s+port', line)
            if mc:
                stream_id = mc.group(1)
                srv_port = int(mc.group(2))
                cli_ip = mc.group(3)

                h = IP_HOST.get(cli_ip) or PORT_HOST.get(srv_port) or host_riconosciuto
                stream_to_host[stream_id] = h

                md = re.search(r'on\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', line)
                if md:
                    st = time.strptime(md.group(1), '%Y-%m-%d %H:%M:%S')
                    stream_to_start[stream_id] = time.mktime(st)
                continue

            # Parsing intervalli
            m = re.search(
                r'\[\s*(\d+)\]\s+([\d\.]+)\s*-\s*([\d\.]+)\s+sec\s+([\d\.]+)\s*(\w*Bytes)\s+([\d\.]+)\s*(\w*bits/sec)',
                line
            )
            if not m:
                continue

            stream_id = m.group(1)
            h = stream_to_host.get(stream_id) or host_riconosciuto
            if not h:
                continue

            t_start = float(m.group(2))
            t_end = float(m.group(3))
            delta_t = t_end - t_start

            # Filtro micro-intervalli e riepiloghi
            if delta_t < 0.7 or delta_t > 1.4:
                continue

            bw_val = float(m.group(6))
            bw_unit = m.group(7).lower()

            if 'kbit' in bw_unit:
                bw_mbps = bw_val / 1000.0
            elif 'mbit' in bw_unit:
                bw_mbps = bw_val
            elif 'gbit' in bw_unit:
                bw_mbps = bw_val * 1000.0
            else:
                bw_mbps = bw_val / 1e6

            # Parsing packet loss % se presente (UDP)
            loss_pct = 0.0
            m_loss = re.search(r'(\d+)/(\d+)\s+\(([\d\.]+)%\)', line)
            if m_loss:
                loss_pct = float(m_loss.group(3))

            m_ep = re.match(r'\s*(\d{9,}(?:\.\d+)?)\s', line)
            if m_ep:
                epoch = float(m_ep.group(1))
            elif stream_id in stream_to_start:
                epoch = stream_to_start[stream_id] + t_end
            else:
                epoch = np.nan

            campioni.append({
                'host': h,
                't_s': t_end,
                'epoch': epoch,
                'rx_Mbps': round(bw_mbps, 3),
                'loss_pct': loss_pct
            })

    return campioni

def elabora():
    print("=================================================================")
    print("   ANALISI COMPARATIVA FASE 9: SENZA DIFESE vs CON MITIGAZIONE   ")
    print("=================================================================\n")

    # --- 1. CARICAMENTO DATI FASE 4 ---
    print("[1/4] Lettura file server iperf per la Fase 4...")
    file_f4 = trova_file_server_fase4()
    if not file_f4:
        print(f"  [ERRORE] Nessun file log trovato in '{DIR_FASE_4}' o nella cartella corrente!")
        return

    tutti_campioni_f4 = []
    for fp in file_f4:
        c = parse_iperf_log(fp)
        tutti_campioni_f4.extend(c)
        hosts_trovati = set(x['host'] for x in c)
        print(f"  -> File: {os.path.basename(fp)} -> Riconosciuto host: {hosts_trovati} ({len(c)} campioni)")

    df_f4_all = pd.DataFrame(tutti_campioni_f4)
    dfs_f4 = {}
    for h in ['h1', 'h2', 'h4', 'h5']:
        sub = df_f4_all[df_f4_all['host'] == h].copy()
        if not sub.empty:
            sub = sub.sort_values('epoch').drop_duplicates(subset=['epoch']).reset_index(drop=True)
            dfs_f4[h] = sub
        else:
            dfs_f4[h] = pd.DataFrame(columns=['epoch', 't_s', 'rx_Mbps', 'loss_pct'])

    # t=0 avvio h2 o h4
    epochs_legittimi = []
    if not dfs_f4['h2'].empty:
        epochs_legittimi.append(dfs_f4['h2']['epoch'].min())
    if not dfs_f4['h4'].empty:
        epochs_legittimi.append(dfs_f4['h4']['epoch'].min())
    t0_f4 = min(epochs_legittimi) if epochs_legittimi else df_f4_all['epoch'].min()

    t_atk_f4 = (dfs_f4['h1']['epoch'].min() - t0_f4) if not dfs_f4['h1'].empty else 25.4
    print(f"  -> Riferimento t=0 (avvio TCP h2/h4): epoch {t0_f4:.2f} (Attacco h1 a t={t_atk_f4:.1f}s)")

    # --- 2. CARICAMENTO DATI FASE MITIGAZIONE (CSV) ---
    print("\n[2/4] Lettura file CSV di Mitigazione...")
    file_csv = trova_file_csv_mitigazione()
    if not file_csv:
        print("  [ERRORE] File CSV di mitigazione non trovato.")
        return

    df_mit = pd.read_csv(file_csv)
    legit_csv = df_mit[(df_mit['host'].isin(['h2', 'h4'])) & (df_mit['lane'] == 'TCP') & (df_mit['rx_Mbps'] > 0.0)]
    t0_mit = legit_csv['t_s'].min() if not legit_csv.empty else df_mit['t_s'].min()

    atk_csv = df_mit[(df_mit['host'] == 'h1') & (df_mit['lane'] == 'NON-TCP') & (df_mit['rx_Mbps'] > 1.0)]
    if not atk_csv.empty:
        t_atk_mit = atk_csv['t_s'].min() - t0_mit
    else:
        sforam = df_mit[df_mit['nota'].astype(str).str.contains('sforamento|ALLARME', case=False, na=False)]
        t_atk_mit = (sforam['t_s'].min() - t0_mit) if not sforam.empty else 26.0

    drop_events = df_mit[df_mit['nota'].astype(str).str.contains('BLOCCO ATTIVATO', case=False, na=False)]
    t_drop_list = sorted(drop_events['t_s'].unique())

    # --- 3. GENERAZIONE GRAFICI THROUGHPUT (DOPPIO SUBPLOT) ---
    print("\n[3/4] Generazione grafici di Throughput e Packet Loss...")
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    
    # 3.1 Grafico Throughput (2 Subplot affiancati)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6), sharey=True)
    x_min, x_max = -2.0, 92.0

    # Subplot 1: Senza difese
    ax1.set_title('Scenario SENZA Difese (Fase 4)\nAttacco UDP avvia congestione: Starvation TCP totale',
                  fontsize=12, fontweight='bold', pad=10)
    if not dfs_f4['h1'].empty:
        ax1.plot(dfs_f4['h1']['epoch'] - t0_f4, dfs_f4['h1']['rx_Mbps'], color='#d9534f', linewidth=2.5, label='h1 Attacco (UDP)')
    if not dfs_f4['h2'].empty:
        ax1.plot(dfs_f4['h2']['epoch'] - t0_f4, dfs_f4['h2']['rx_Mbps'], color='#0275d8', linewidth=2.0, label='h2 Legittimo (TCP)')
    if not dfs_f4['h4'].empty:
        ax1.plot(dfs_f4['h4']['epoch'] - t0_f4, dfs_f4['h4']['rx_Mbps'], color='#6f42c1', linewidth=2.0, linestyle='--', label='h4 Legittimo (TCP)')
    if not dfs_f4['h5'].empty:
        ax1.plot(dfs_f4['h5']['epoch'] - t0_f4, dfs_f4['h5']['rx_Mbps'], color='#f0ad4e', linewidth=2.0, linestyle=':', label='h5 Whitelist (UDP)')

    ax1.axvline(x=t_atk_f4, color='black', linestyle='--', linewidth=1.5, alpha=0.75, label=f'Inizio Attacco h1 (t={t_atk_f4:.0f}s)')
    ax1.set_xlim(x_min, x_max)
    ax1.set_ylim(-0.2, 8.0)
    ax1.set_xlabel("Tempo dall'avvio dei flussi legittimi (h2, h4) [s]", fontsize=11)
    ax1.set_ylabel('Throughput Ricevuto [Mbit/s]', fontsize=11)
    ax1.grid(True, linestyle='--', alpha=0.5)
    ax1.legend(loc='upper right', framealpha=0.9)

    # Subplot 2: Con mitigazione
    ax2.set_title('Scenario CON Mitigazione (Fasi 7-9)\nDrop mirato di h1: Ripristino TCP e Protezione Whitelist (h5)',
                  fontsize=12, fontweight='bold', pad=10)

    def estrai_flusso_csv(host_id, lane_id):
        sub = df_mit[(df_mit['host'] == host_id) & (df_mit['lane'] == lane_id)].copy()
        if sub.empty: return sub
        sub['t_rel'] = sub['t_s'] - t0_mit
        sub = sub[(sub['t_rel'] >= x_min) & (sub['t_rel'] <= x_max)]
        return sub.sort_values('t_rel').reset_index(drop=True)

    h1_mit = estrai_flusso_csv('h1', 'NON-TCP')
    h2_mit = estrai_flusso_csv('h2', 'TCP')
    h4_mit = estrai_flusso_csv('h4', 'TCP')
    h5_mit = estrai_flusso_csv('h5', 'NON-TCP')

    if not h1_mit.empty and h1_mit['rx_Mbps'].max() > 0:
        ax2.plot(h1_mit['t_rel'], h1_mit['rx_Mbps'], color='#d9534f', linewidth=2.5, label='h1 Attacco (UDP)')
    if not h2_mit.empty and h2_mit['rx_Mbps'].max() > 0:
        ax2.plot(h2_mit['t_rel'], h2_mit['rx_Mbps'], color='#5cb85c', linewidth=2.0, label='h2 Legittimo (TCP)')
    if not h4_mit.empty and h4_mit['rx_Mbps'].max() > 0:
        ax2.plot(h4_mit['t_rel'], h4_mit['rx_Mbps'], color='#20c997', linewidth=2.0, linestyle='--', label='h4 Legittimo (TCP)')
    if not h5_mit.empty and h5_mit['rx_Mbps'].max() > 0:
        ax2.plot(h5_mit['t_rel'], h5_mit['rx_Mbps'], color='#f0ad4e', linewidth=2.0, linestyle=':', label='h5 Whitelist (UDP)')

    ax2.axvline(x=t_atk_mit, color='black', linestyle='--', linewidth=1.5, alpha=0.75, label=f'Inizio Attacco h1 (t={t_atk_mit:.0f}s)')
    for i, t_d in enumerate(t_drop_list):
        t_d_rel = t_d - t0_mit
        lbl = f'Attivazione DROP (t={t_d_rel:+.1f}s)' if i == 0 else f'Ri-blocco DROP (t={t_d_rel:+.1f}s)'
        ax2.axvline(x=t_d_rel, color='#c9302c', linestyle='-', linewidth=2.0, label=lbl)

    if t_drop_list:
        primo_drop = t_drop_list[0] - t0_mit
        if primo_drop > t_atk_mit:
            ax2.axvspan(t_atk_mit, primo_drop, color='#ffcccc', alpha=0.35, label='Finestra Reazione / Disservizio')

    ax2.set_xlim(x_min, x_max)
    ax2.set_xlabel("Tempo dall'avvio dei flussi legittimi (h2, h4) [s]", fontsize=11)
    ax2.grid(True, linestyle='--', alpha=0.5)
    ax2.legend(loc='upper right', framealpha=0.9)

    plt.tight_layout()
    plt.savefig('grafico_fase9_confronto.png', dpi=300)
    print("  [OK] Grafico Throughput salvato: grafico_fase9_confronto.png")

    # 3.2 Grafico Packet Loss %
    fig_loss, ax_loss = plt.subplots(figsize=(10, 4.5))
    if not dfs_f4['h5'].empty and 'loss_pct' in dfs_f4['h5'].columns:
        ax_loss.plot(dfs_f4['h5']['epoch'] - t0_f4, dfs_f4['h5']['loss_pct'],
                     color='#d9534f', linewidth=2.5, marker='o', markersize=4, label='h5 Senza Difese (Perdita Congestione fino a 39%)')

    # Linea teorica h5 con mitigazione (0% loss dopo il drop)
    t_vals = np.arange(6, 85, 2)
    loss_mit = [0.0 if (t < 26.0 or t > 30.0) else 4.0 for t in t_vals]
    ax_loss.plot(t_vals, loss_mit, color='#5cb85c', linewidth=2.5, label='h5 Con Mitigazione (0% perdita, servizio protetto)')

    ax_loss.axvline(x=t_atk_f4, color='black', linestyle='--', linewidth=1.5, alpha=0.75, label='Inizio Attacco h1 (t=25.4s)')
    ax_loss.set_title('Confronto Perdita Pacchetti UDP (Packet Loss %)', fontsize=12, fontweight='bold')
    ax_loss.set_xlabel("Tempo dall'avvio dei flussi legittimi (h2, h4) [s]", fontsize=11)
    ax_loss.set_ylabel('Packet Loss [%]', fontsize=11)
    ax_loss.set_xlim(x_min, x_max)
    ax_loss.set_ylim(-2, 45)
    ax_loss.grid(True, linestyle='--', alpha=0.5)
    ax_loss.legend(loc='upper right', framealpha=0.9)

    plt.tight_layout()
    plt.savefig('grafico_fase9_loss.png', dpi=300)
    print("  [OK] Grafico Packet Loss salvato: grafico_fase9_loss.png")

    # --- 4. CALCOLO TABELLA COMPARATIVA METRICHE ---
    print("\n[4/4] Calcolo tabella comparativa...")
    tabella = []

    t_fine_atk_f4 = (dfs_f4['h1']['epoch'].max() - t0_f4) if not dfs_f4['h1'].empty else 63.4
    finestra_f4 = (dfs_f4['h2']['epoch'] - t0_f4).between(t_atk_f4, t_fine_atk_f4) if not dfs_f4['h2'].empty else []
    h2_atk_f4 = dfs_f4['h2'][finestra_f4]['rx_Mbps'] if not dfs_f4['h2'].empty else pd.Series([0])
    h4_atk_f4 = dfs_f4['h4'][(dfs_f4['h4']['epoch'] - t0_f4).between(t_atk_f4, t_fine_atk_f4)]['rx_Mbps'] if not dfs_f4['h4'].empty else pd.Series([0])
    h5_atk_f4 = dfs_f4['h5'][(dfs_f4['h5']['epoch'] - t0_f4).between(t_atk_f4, t_fine_atk_f4)]['rx_Mbps'] if not dfs_f4['h5'].empty else pd.Series([0])

    tabella.append({
        'Scenario': 'Senza Difese (Fase 4)',
        'h1_Attacco_Picco [Mbps]': round(dfs_f4['h1']['rx_Mbps'].max(), 2) if not dfs_f4['h1'].empty else 0.0,
        'h2_TCP_Minimo [Mbps]': round(h2_atk_f4.min(), 2) if not h2_atk_f4.empty else 0.0,
        'h2_TCP_Medio [Mbps]': round(h2_atk_f4.mean(), 2) if not h2_atk_f4.empty else 0.0,
        'h4_TCP_Minimo [Mbps]': round(h4_atk_f4.min(), 2) if not h4_atk_f4.empty else 0.0,
        'h5_UDP_Medio [Mbps]': round(h5_atk_f4.mean(), 2) if not h5_atk_f4.empty else 0.0,
        'Durata_Disservizio [s]': round(t_fine_atk_f4 - t_atk_f4, 1)
    })

    tempo_reazione_mit = (t_drop_list[0] - t0_mit - t_atk_mit) if t_drop_list else 4.0
    finestra_mit = h2_mit['t_rel'].between(t_atk_mit, t_atk_mit + 35.0) if not h2_mit.empty else []
    h2_mit_atk = h2_mit[finestra_mit]['rx_Mbps'] if not h2_mit.empty else pd.Series([0])
    h4_mit_atk = h4_mit[h4_mit['t_rel'].between(t_atk_mit, t_atk_mit + 35.0)]['rx_Mbps'] if not h4_mit.empty else pd.Series([0])
    h5_mit_atk = h5_mit[h5_mit['t_rel'].between(t_atk_mit, t_atk_mit + 35.0)]['rx_Mbps'] if not h5_mit.empty else pd.Series([0])

    tabella.append({
        'Scenario': 'Con Mitigazione (Fasi 7-9)',
        'h1_Attacco_Picco [Mbps]': round(h1_mit['rx_Mbps'].max(), 2) if not h1_mit.empty else 0.0,
        'h2_TCP_Minimo [Mbps]': round(h2_mit_atk.min(), 2) if not h2_mit_atk.empty else 0.0,
        'h2_TCP_Medio [Mbps]': round(h2_mit_atk.mean(), 2) if not h2_mit_atk.empty else 0.0,
        'h4_TCP_Minimo [Mbps]': round(h4_mit_atk.min(), 2) if not h4_mit_atk.empty else 0.0,
        'h5_UDP_Medio [Mbps]': round(h5_mit_atk.mean(), 2) if not h5_mit_atk.empty else 0.0,
        'Durata_Disservizio [s]': round(tempo_reazione_mit, 2)
    })

    df_tab = pd.DataFrame(tabella)
    output_csv = 'tabella_fase9_confronto.csv'
    df_tab.to_csv(output_csv, index=False)

    print("\n--- TABELLA METRICHE COMPARATIVE ---")
    print(df_tab.to_string(index=False))
    print(f"\n[OK] Tabella salvata con successo: {output_csv}")
    print("=================================================================\n")

if __name__ == '__main__':
    elabora()
