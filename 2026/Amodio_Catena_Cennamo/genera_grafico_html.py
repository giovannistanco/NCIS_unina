# -*- coding: utf-8 -*-
"""
genera_grafico_html.py - Rigenera la dashboard HTML interattiva dai log reali

Convenzione:
  - t=0: istante di inizio dei flussi legittimi h2 e h4.
  - t ≈ 6s: avvio h5.
  - t ≈ 25s: avvio attacco h1.
"""

import os
import re
import json
import pandas as pd
from fase9_analisi_confronto import (
    trova_file_server_fase4,
    trova_file_csv_mitigazione,
    parse_iperf_log
)

def genera_html():
    print("[1/3] Parsing campioni Fase 4 (server txt)...")
    file_f4 = trova_file_server_fase4()
    campioni_f4 = []
    for fp in file_f4:
        c = parse_iperf_log(fp)
        campioni_f4.extend(c)

    df_f4_all = pd.DataFrame(campioni_f4)
    data_fase4_json = {}

    if not df_f4_all.empty:
        # t=0 = min tra h2 e h4
        epochs_legittimi = []
        for h in ['h2', 'h4']:
            sub_h = df_f4_all[df_f4_all['host'] == h]
            if not sub_h.empty:
                epochs_legittimi.append(sub_h['epoch'].min())
        t0_f4 = min(epochs_legittimi) if epochs_legittimi else df_f4_all['epoch'].min()

        for h in ['h1', 'h2', 'h4', 'h5']:
            sub = df_f4_all[df_f4_all['host'] == h].copy()
            if sub.empty:
                data_fase4_json[h] = []
                continue
            sub = sub.sort_values('epoch').drop_duplicates(subset=['epoch']).reset_index(drop=True)
            serie = []
            for _, r in sub.iterrows():
                t_rel = round(float(r['epoch'] - t0_f4), 1)
                if -2.0 <= t_rel <= 90.0:
                    serie.append({'t': t_rel, 'v': round(float(r['rx_Mbps']), 2)})
            data_fase4_json[h] = serie
    else:
        data_fase4_json = {h: [] for h in ['h1', 'h2', 'h4', 'h5']}

    print("[2/3] Parsing campioni Fase Mitigazione (CSV)...")
    file_csv = trova_file_csv_mitigazione()
    data_mit_json = {}

    if file_csv and os.path.exists(file_csv):
        df_mit = pd.read_csv(file_csv)
        legit_csv = df_mit[(df_mit['host'].isin(['h2', 'h4'])) & (df_mit['lane'] == 'TCP') & (df_mit['rx_Mbps'] > 0.0)]
        t0_mit = legit_csv['t_s'].min() if not legit_csv.empty else df_mit['t_s'].min()

        for h, lane in [('h1', 'NON-TCP'), ('h2', 'TCP'), ('h4', 'TCP'), ('h5', 'NON-TCP')]:
            sub = df_mit[(df_mit['host'] == h) & (df_mit['lane'] == lane)].copy()
            serie = []
            for _, r in sub.iterrows():
                t_rel = round(float(r['t_s'] - t0_mit), 1)
                if -2.0 <= t_rel <= 90.0:
                    nota = str(r.get('nota', '')) if pd.notna(r.get('nota')) else ''
                    item = {'t': t_rel, 'v': round(float(r['rx_Mbps']), 2)}
                    if 'BLOCCO' in nota or 'ALLARME' in nota or 'sblocco' in nota or 'sforamento' in nota:
                        item['note'] = nota
                    serie.append(item)
            data_mit_json[h] = serie
    else:
        data_mit_json = {h: [] for h in ['h1', 'h2', 'h4', 'h5']}

    print("[3/3] Aggiornamento confronto_fase9_interattivo.html...")
    target_html = 'confronto_fase9_interattivo.html'
    if not os.path.exists(target_html):
        return

    with open(target_html, 'r', encoding='utf-8') as f:
        html = f.read()

    html = re.sub(r'const dataFase4 = \{.*?\};', f'const dataFase4 = {json.dumps(data_fase4_json, indent=2)};', html, flags=re.DOTALL)
    html = re.sub(r'const dataFaseMit = \{.*?\};', f'const dataFaseMit = {json.dumps(data_mit_json, indent=2)};', html, flags=re.DOTALL)

    with open(target_html, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"  [OK] Dashboard HTML sincronizzata con t=0 avvio h2/h4: {target_html}")

if __name__ == '__main__':
    genera_html()
