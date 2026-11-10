# dashboard/pages/ml_analysis.py
# ══════════════════════════════════════════════════════════
# Modulo 2: Analisi ML & Classificazione a due livelli
#   L1 → Port/MAC-based (deterministico, ground truth)
#   L2 → K-Means su packet statistics (non supervisionato)
# ══════════════════════════════════════════════════════════
from __future__ import annotations  # compatibilità Python 3.8 per i type hint

import streamlit as st
import pandas as pd

from dashboard.utils import load_csv, classify_l1, classify_l2_ml


def _load_data(use_live: bool, uploaded_file) -> tuple[pd.DataFrame | None, str | None]:
    """Seleziona la sorgente dati: live CSV o file caricato."""
    if use_live:
        return load_csv()
    if uploaded_file is None:
        return None, None   # nessun file ancora caricato, silenzioso
    try:
        df = pd.read_csv(uploaded_file).dropna()
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['mb_count']  = df['byte_count'] / 1_000_000
        df['src_name']  = df['src']
        df['dst_name']  = df['dst']
        return df, None
    except Exception as exc:
        return None, f"Errore nella lettura del file: {exc}"


def render() -> None:
    """Renderizza la pagina Analisi ML & Classificazione."""

    st.markdown("""
    <div class="hero-header">
        <p class="hero-title">🧠 Analisi ML & Classificazione</p>
        <p class="hero-subtitle">
            Classificazione a due livelli: Deterministica (Port/MAC-based) + Machine Learning (K-Means)
        </p>
    </div>
    """, unsafe_allow_html=True)

    # ── Sorgente dati ──
    use_live = st.toggle("Usa dataset live dal controller", value=True)
    uploaded = None
    if not use_live:
        uploaded = st.file_uploader("Carica `traffic_data.csv` storico", type=["csv"])

    df_in, err = _load_data(use_live, uploaded)

    if err:
        st.error(f"⚠️ {err}")
        return
    if df_in is None:
        if not use_live:
            st.info("Seleziona un file CSV da caricare.")
        return

    st.success(f"✅ Dataset pronto — **{len(df_in):,}** campioni")
    st.markdown("---")

    # ════════════════════════════════════════════
    # 1. Esplorazione dataset
    # ════════════════════════════════════════════
    st.markdown("### 1️⃣ Esplorazione Dataset")
    cc1, cc2, cc3 = st.columns(3)
    cc1.metric("Campioni totali",  f"{len(df_in):,}")
    cc2.metric("Switch monitorati", str(df_in['dpid'].nunique()))
    cc3.metric("Flussi unici",     str(df_in.groupby(['src', 'dst']).ngroups))

    with st.expander("Mostra ultime 10 righe del dataset"):
        st.dataframe(df_in.tail(10), use_container_width=True, hide_index=True)

    st.markdown("---")


    # ════════════════════════════════════════════
    # 2. Classificazione L1 – Port/MAC-based
    # ════════════════════════════════════════════
    st.markdown("### 2️⃣ Classificazione Deterministica – Port/MAC-based")
    st.markdown("""
    <div class="glass-card">
    <div style="color:#94a3b8;font-size:0.9rem;">
    <b style="color:#f59e0b;">Classificazione deterministica</b> — ogni flusso viene identificato con
    i MAC address src/dst. Equivale al matching per <b>porta TCP/UDP</b> nei flow-entry OpenFlow
    e fornisce il <b>ground truth</b> per confrontare il modello ML.
    </div>
    </div>
    """, unsafe_allow_html=True)

    df_l1 = df_in.copy()
    df_l1['Classe L1'] = df_l1.apply(classify_l1, axis=1)

    la, lb = st.columns([2, 3])
    with la:
        st.markdown("**Distribuzione Classi (Deterministica)**")
        d = df_l1['Classe L1'].value_counts().reset_index()
        d.columns = ['Classe', 'Conteggio']
        st.dataframe(d, use_container_width=True, hide_index=True)
    with lb:
        st.markdown("**Volume medio per Classe (MB)**")
        v = df_l1.groupby('Classe L1')['mb_count'].mean().reset_index()
        v.columns = ['Classe', 'MB medio']
        st.bar_chart(v.set_index('Classe'), color="#f59e0b", height=200)

    st.markdown("---")

    # ════════════════════════════════════════════
    # 3. Classificazione Statistica – K-Means ML
    # ════════════════════════════════════════════
    st.markdown("### 3️⃣ Classificazione Statistica – K-Means (Packet Statistics)")
    st.markdown("""
    <div class="glass-card">
    <div style="color:#94a3b8;font-size:0.9rem;">
    <b style="color:#a78bfa;">K-Means non supervisionato</b> — analizza esclusivamente
    <code>byte_count</code> e <code>packet_count</code> normalizzati con StandardScaler.
    <b>Non conosce</b> MAC, IP o porte: scopre autonomamente le categorie di traffico
    dalle sole statistiche di pacchetto — l'approccio richiesto dall'<b>Estensione 2</b>.
    </div>
    </div>
    """, unsafe_allow_html=True)

    df_ml = classify_l2_ml(df_in.copy())

    ml1, ml2 = st.columns([3, 2])
    with ml1:
        st.markdown("**Scatter: Pacchetti vs Byte (colore = classe ML)**")
        st.scatter_chart(df_ml, x='packet_count', y='byte_count', color='ML_Class', height=320)
    with ml2:
        st.markdown("**Distribuzione Classi ML**")
        md = df_ml['ML_Class'].value_counts().reset_index()
        md.columns = ['Classe ML', 'Conteggio']
        st.dataframe(md, use_container_width=True, hide_index=True)

        st.markdown("**Statistiche per Classe ML**")
        ms = (df_ml.groupby('ML_Class')['mb_count']
                   .agg(['mean', 'max', 'min'])
                   .round(3)
                   .reset_index()
                   .rename(columns={'ML_Class': 'Classe', 'mean': 'Media MB',
                                    'max': 'Max MB', 'min': 'Min MB'}))
        st.dataframe(ms, use_container_width=True, hide_index=True)

    st.markdown("---")

    # ════════════════════════════════════════════
    # 4. Confronto L1 ↔ L2
    # ════════════════════════════════════════════
    st.markdown("### 4️⃣ Confronto Deterministico ↔ Machine Learning")
    st.markdown(
        '<div class="info-box">L\'alta coerenza tra i due classificatori dimostra che le '
        '<b>statistiche di traffico</b> (byte + pacchetti) sono sufficienti a discriminare le slice '
        '— validando l\'approccio di classificazione avanzata dell\'Estensione 2.</div>',
        unsafe_allow_html=True
    )

    df_cmp = df_l1.copy()
    df_cmp['Classe L2 (ML)'] = df_ml['ML_Class'].values

    def _coerente(r: pd.Series) -> bool:
        return (('Video' in r['Classe L1'] and 'Alta'  in r['Classe L2 (ML)']) or
                ('Dati'  in r['Classe L1'] and 'Bassa' in r['Classe L2 (ML)']))

    df_cmp['✅ Coerente'] = df_cmp.apply(_coerente, axis=1)
    acc = df_cmp['✅ Coerente'].mean() * 100

    a1, a2 = st.columns(2)
    a1.metric("🎯 Coerenza Deterministico ↔ ML", f"{acc:.1f}%",
              delta="Alta" if acc > 80 else "Da analizzare")
    a2.metric("📊 Campioni analizzati", f"{len(df_cmp):,}")

    st.dataframe(
        df_cmp[['timestamp', 'src_name', 'dst_name',
                'packet_count', 'mb_count', 'Classe L1', 'Classe L2 (ML)', '✅ Coerente']]
              .rename(columns={'src_name': 'Src', 'dst_name': 'Dst', 'mb_count': 'Volume (MB)'})
              .sort_values('timestamp', ascending=False)
              .head(50),
        use_container_width=True, hide_index=True
    )
