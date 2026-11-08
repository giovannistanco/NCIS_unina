# dashboard/pages/live_monitor.py
# ══════════════════════════════════════════════════════════
# Modulo 1: Monitoraggio Live
# Mostra traffico in tempo reale per le due slice (finestra
# mobile sugli ultimi 30 campioni) + classificazione L1.
# ══════════════════════════════════════════════════════════
import time
import streamlit as st

from dashboard.utils import (
    UPPER_SLICE, LOWER_SLICE, COLOR_FAST, COLOR_SLOW, DYNAMIC_SLICING_THRESHOLD_MBPS,
    load_csv, classify_l1, calc_bw_mbps, is_fast_lane_active
)


def render() -> None:
    """Renderizza la pagina Live Monitor e schedula il rerun automatico."""

    # Hero header
    st.markdown("""
    <div class="hero-header">
        <p class="hero-title">🔴 Network Traffic Monitor</p>
        <p class="hero-subtitle">Finestra mobile — ultimi 30 campioni · Classificazione Deterministica in tempo reale</p>
        <span class="badge-live">LIVE</span>
    </div>
    """, unsafe_allow_html=True)

    df, err = load_csv()

    if err:
        st.error(f"⚠️ {err}")
        st.info("Avvia Mininet e il controller Ryu per raccogliere dati nel CSV.")
        time.sleep(5)
        st.rerun()
        return

    # ── Filtra per slice (solo switch S1, dpid=1) ──
    video_df = df[
        (df['dpid'] == 1) &
        (df['src']  == UPPER_SLICE['src']) &
        (df['dst']  == UPPER_SLICE['dst'])
    ].tail(30).copy()

    dati_df = df[
        (df['dpid'] == 1) &
        (df['src']  == LOWER_SLICE['src']) &
        (df['dst']  == LOWER_SLICE['dst'])
    ].tail(30).copy()

    # ── Metriche ──
    bw_video = calc_bw_mbps(video_df)
    bw_dati  = calc_bw_mbps(dati_df)
    fast_lane = is_fast_lane_active(bw_video)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("🎬 BW Video (est.)", f"{bw_video:.2f} Mbps")
    c2.metric("📦 Volume Video",
              f"{video_df['mb_count'].iloc[-1]:.2f} MB" if not video_df.empty else "0 MB",
              delta="cumulativo")
    c3.metric("📡 BW Dati (est.)", f"{bw_dati:.2f} Mbps")
    c4.metric("📦 Volume Dati",
              f"{dati_df['mb_count'].iloc[-1]:.2f} MB" if not dati_df.empty else "0 MB",
              delta="cumulativo")

    # ── Banner Dynamic Slicing ──
    fl_color = COLOR_FAST if fast_lane else COLOR_SLOW
    fl_text  = (
        "⚡ Fast Lane ATTIVA — Dati su slice 10 Mbps (video inattivo)"
        if fast_lane else
        "🛑 Fast Lane INATTIVA — Video attivo, dati su slice 1 Mbps"
    )
    st.markdown(f"""
    <div class="glass-card" style="border-color:{fl_color}40; margin-top:0.5rem;">
        <div style="font-size:0.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:0.4rem;">
            ⚡ Dynamic Slicing
        </div>
        <div style="font-size:1.05rem;font-weight:600;color:{fl_color};">{fl_text}</div>
        <div style="font-size:0.8rem;color:#64748b;margin-top:0.3rem;">
            Soglia: {DYNAMIC_SLICING_THRESHOLD_MBPS} Mbps · Banda video attuale: {bw_video:.3f} Mbps
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Grafici area + linea pacchetti ──
    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            '<div class="glass-card slice-upper">'
            '<div style="color:#f59e0b;font-size:0.78rem;text-transform:uppercase;">'
            '🎬 Upper Slice · H1→H3 · 10 Mbps</div></div>',
            unsafe_allow_html=True
        )
        if not video_df.empty:
            st.area_chart(
                video_df.set_index('timestamp')[['mb_count']].rename(columns={'mb_count': 'MB'}),
                color="#f59e0b", height=220
            )
        else:
            st.info("⏳ Nessun dato. Avvia: `h1 iperf -c 10.0.0.3 -t 60 -b 8M`")

    with col2:
        st.markdown(
            '<div class="glass-card slice-lower">'
            '<div style="color:#6366f1;font-size:0.78rem;text-transform:uppercase;">'
            '📄 Lower Slice · H2→H4 · 1 Mbps</div></div>',
            unsafe_allow_html=True
        )
        if not dati_df.empty:
            st.area_chart(
                dati_df.set_index('timestamp')[['mb_count']].rename(columns={'mb_count': 'MB'}),
                color="#6366f1", height=220
            )
        else:
            st.info("⏳ Nessun dato. Avvia: `h2 iperf -c 10.0.0.4 -t 60 -b 1M`")


    # ── Auto-refresh non bloccante ──
    time.sleep(5)
    st.rerun()
