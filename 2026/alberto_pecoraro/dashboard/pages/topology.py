# dashboard/pages/topology.py
# ══════════════════════════════════════════════════════════
# Modulo 3: Topologia di Rete
# SVG della rete SDN a 6 switch con stato live del
# Dynamic Slicing (colori si adattano alla slice attiva).
# ══════════════════════════════════════════════════════════
import streamlit as st
import pandas as pd

from dashboard.utils import (
    UPPER_SLICE, LOWER_SLICE, COLOR_UPPER, COLOR_LOWER, COLOR_FAST, COLOR_SLOW,
    COLOR_ACCENT, COLOR_RYU, DYNAMIC_SLICING_THRESHOLD_MBPS,
    load_csv, calc_bw_mbps, is_fast_lane_active
)


def _build_svg(uc: str, dc: str, bw_lbl: str) -> str:
    """
    Genera l'SVG della topologia SDN.
    
    Args:
        uc:     colore upper slice
        dc:     colore data path (lower o fast lane)
        bw_lbl: etichetta banda sul percorso dati ("1 Mbps" o "10 Mbps")
    """
    return f"""<svg viewBox="0 0 800 420" xmlns="http://www.w3.org/2000/svg"
     style="width:100%;max-width:860px;background:transparent;">
  <defs>
    <marker id="arr_u" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0, 8 3, 0 6" fill="{uc}"/>
    </marker>
    <marker id="arr_d" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0, 8 3, 0 6" fill="{dc}"/>
    </marker>
  </defs>

  <!-- ══ UPPER SLICE LINKS ══ -->
  <line x1="340" y1="197" x2="235" y2="117" stroke="{uc}" stroke-width="2.5" stroke-dasharray="7,3" marker-end="url(#arr_u)" opacity="0.85"/>
  <line x1="235" y1="110" x2="510" y2="110" stroke="{uc}" stroke-width="2.5" stroke-dasharray="7,3" marker-end="url(#arr_u)" opacity="0.85"/>
  <line x1="570" y1="117" x2="660" y2="197" stroke="{uc}" stroke-width="2.5" stroke-dasharray="7,3" marker-end="url(#arr_u)" opacity="0.85"/>

  <!-- ══ LOWER / DATA SLICE LINKS ══ -->
  <line x1="340" y1="213" x2="235" y2="297" stroke="{dc}" stroke-width="2" stroke-dasharray="5,4" marker-end="url(#arr_d)" opacity="0.8"/>
  <line x1="235" y1="305" x2="510" y2="305" stroke="{dc}" stroke-width="2" stroke-dasharray="5,4" marker-end="url(#arr_d)" opacity="0.8"/>
  <line x1="570" y1="297" x2="660" y2="213" stroke="{dc}" stroke-width="2" stroke-dasharray="5,4" marker-end="url(#arr_d)" opacity="0.8"/>

  <!-- ══ HOST ↔ SWITCH LINKS ══ -->
  <line x1="90"  y1="110" x2="175" y2="110" stroke="{uc}" stroke-width="1.8" opacity="0.5"/>
  <line x1="90"  y1="305" x2="175" y2="305" stroke="{dc}" stroke-width="1.8" opacity="0.5"/>
  <line x1="175" y1="110" x2="340" y2="197" stroke="{uc}" stroke-width="1.2" stroke-dasharray="3,4" opacity="0.4"/>
  <line x1="175" y1="305" x2="340" y2="213" stroke="{dc}" stroke-width="1.2" stroke-dasharray="3,4" opacity="0.4"/>
  <line x1="660" y1="197" x2="720" y2="110" stroke="{uc}" stroke-width="1.2" stroke-dasharray="3,4" opacity="0.4"/>
  <line x1="660" y1="213" x2="720" y2="305" stroke="{dc}" stroke-width="1.2" stroke-dasharray="3,4" opacity="0.4"/>
  <line x1="720" y1="110" x2="755" y2="110" stroke="{uc}" stroke-width="1.8" opacity="0.5"/>
  <line x1="720" y1="305" x2="755" y2="305" stroke="{dc}" stroke-width="1.8" opacity="0.5"/>

  <!-- ══ SWITCH NODES ══ -->
  <!-- S1 (core entry) -->
  <rect x="340" y="185" width="60" height="40" rx="8" fill="#1e293b" stroke="{COLOR_ACCENT}" stroke-width="2.5"/>
  <text x="370" y="210" text-anchor="middle" fill="{COLOR_ACCENT}" font-family="monospace" font-size="14" font-weight="bold">S1</text>

  <!-- S2 (upper) -->
  <rect x="175" y="90" width="60" height="40" rx="8" fill="#1e293b" stroke="{uc}" stroke-width="2"/>
  <text x="205" y="115" text-anchor="middle" fill="{uc}" font-family="monospace" font-size="14" font-weight="bold">S2</text>

  <!-- S3 (lower) -->
  <rect x="175" y="285" width="60" height="40" rx="8" fill="#1e293b" stroke="{dc}" stroke-width="2"/>
  <text x="205" y="310" text-anchor="middle" fill="{dc}" font-family="monospace" font-size="14" font-weight="bold">S3</text>

  <!-- S4 (upper) -->
  <rect x="510" y="90" width="60" height="40" rx="8" fill="#1e293b" stroke="{uc}" stroke-width="2"/>
  <text x="540" y="115" text-anchor="middle" fill="{uc}" font-family="monospace" font-size="14" font-weight="bold">S4</text>

  <!-- S5 (lower) -->
  <rect x="510" y="285" width="60" height="40" rx="8" fill="#1e293b" stroke="{dc}" stroke-width="2"/>
  <text x="540" y="310" text-anchor="middle" fill="{dc}" font-family="monospace" font-size="14" font-weight="bold">S5</text>

  <!-- S6 (core exit) -->
  <rect x="660" y="185" width="60" height="40" rx="8" fill="#1e293b" stroke="{COLOR_ACCENT}" stroke-width="2.5"/>
  <text x="690" y="210" text-anchor="middle" fill="{COLOR_ACCENT}" font-family="monospace" font-size="14" font-weight="bold">S6</text>

  <!-- ══ HOST NODES ══ -->
  <circle cx="60"  cy="110" r="26" fill="#0f172a" stroke="{uc}" stroke-width="2.5"/>
  <text x="60"  y="106" text-anchor="middle" font-size="17">💻</text>
  <text x="60"  y="121" text-anchor="middle" fill="{uc}" font-family="sans-serif" font-size="12" font-weight="600">H1</text>

  <circle cx="60"  cy="305" r="26" fill="#0f172a" stroke="{dc}" stroke-width="2.5"/>
  <text x="60"  y="301" text-anchor="middle" font-size="17">💻</text>
  <text x="60"  y="316" text-anchor="middle" fill="{dc}" font-family="sans-serif" font-size="12" font-weight="600">H2</text>

  <circle cx="755" cy="110" r="26" fill="#0f172a" stroke="{uc}" stroke-width="2.5"/>
  <text x="755" y="106" text-anchor="middle" font-size="17">🖥️</text>
  <text x="755" y="121" text-anchor="middle" fill="{uc}" font-family="sans-serif" font-size="12" font-weight="600">H3</text>

  <circle cx="755" cy="305" r="26" fill="#0f172a" stroke="{dc}" stroke-width="2.5"/>
  <text x="755" y="301" text-anchor="middle" font-size="17">🖥️</text>
  <text x="755" y="316" text-anchor="middle" fill="{dc}" font-family="sans-serif" font-size="12" font-weight="600">H4</text>

  <!-- ══ BANDWIDTH LABELS ══ -->
  <text x="360" y="82"  text-anchor="middle" fill="{uc}" font-family="monospace" font-size="10" opacity="0.8">10 Mbps</text>
  <text x="540" y="82"  text-anchor="middle" fill="{uc}" font-family="monospace" font-size="10" opacity="0.8">10 Mbps</text>
  <text x="360" y="358" text-anchor="middle" fill="{dc}" font-family="monospace" font-size="10" opacity="0.8">{bw_lbl}</text>
  <text x="540" y="358" text-anchor="middle" fill="{dc}" font-family="monospace" font-size="10" opacity="0.8">{bw_lbl}</text>

  <!-- ══ CONTROLLER ══ -->
  <rect x="320" y="15" width="130" height="32" rx="8" fill="rgba(14,165,233,0.1)" stroke="{COLOR_RYU}" stroke-width="1.5"/>
  <text x="385" y="35" text-anchor="middle" fill="{COLOR_RYU}" font-family="sans-serif" font-size="12" font-weight="600">🎛️ Ryu Controller</text>
  <line x1="370" y1="47" x2="370" y2="185" stroke="{COLOR_RYU}" stroke-width="1" stroke-dasharray="4,3" opacity="0.4"/>
</svg>"""


def render() -> None:
    """Renderizza la pagina Topologia di Rete."""

    st.markdown("""
    <div class="hero-header">
        <p class="hero-title">🗺️ Topologia di Rete SDN</p>
        <p class="hero-subtitle">Topologia a 6 switch con stato live del Dynamic Slicing</p>
    </div>
    """, unsafe_allow_html=True)

    # ── Stato live ──
    df_t, _ = load_csv()
    bw_v = 0.0
    if df_t is not None:
        vt   = df_t[(df_t['dpid'] == 1) & (df_t['src'] == UPPER_SLICE['src'])].tail(10)
        bw_v = calc_bw_mbps(vt)
    fast     = is_fast_lane_active(bw_v)
    dc       = COLOR_FAST if fast else COLOR_LOWER
    fl_c     = COLOR_FAST if fast else COLOR_SLOW
    fl_label = "⚡ Fast Lane ATTIVA" if fast else "🛑 Slow Lane"
    fl_desc  = "Dati su 10 Mbps" if fast else "Dati su 1 Mbps"
    bw_lbl   = "10 Mbps (fast)" if fast else "1 Mbps"

    # ── Riquadri stato ──
    sc1, sc2, sc3 = st.columns(3)
    with sc1:
        st.markdown(f"""
        <div class="glass-card" style="text-align:center;">
            <div style="color:{COLOR_UPPER};font-size:1.1rem;font-weight:700;">🎬 Upper Slice</div>
            <div style="color:#94a3b8;font-size:0.82rem;margin-top:0.3rem;">S1→S2→S4→S6 · 10 Mbps</div>
            <div style="color:{COLOR_UPPER};">H1 ↔ H3 (Video)</div>
        </div>""", unsafe_allow_html=True)
    with sc2:
        st.markdown(f"""
        <div class="glass-card" style="text-align:center;">
            <div style="color:{COLOR_LOWER};font-size:1.1rem;font-weight:700;">📡 Lower Slice</div>
            <div style="color:#94a3b8;font-size:0.82rem;margin-top:0.3rem;">S1→S3→S5→S6 · 1 Mbps</div>
            <div style="color:{COLOR_LOWER};">H2 ↔ H4 (Dati)</div>
        </div>""", unsafe_allow_html=True)
    with sc3:
        st.markdown(f"""
        <div class="glass-card" style="text-align:center;border-color:{fl_c}40;">
            <div style="color:{fl_c};font-size:1.1rem;font-weight:700;">{fl_label}</div>
            <div style="color:#94a3b8;font-size:0.82rem;margin-top:0.3rem;">Dynamic Slicing</div>
            <div style="color:{fl_c};">{fl_desc}</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")

    # ── SVG Topologia ──
    svg = _build_svg(uc=COLOR_UPPER, dc=dc, bw_lbl=bw_lbl)
    st.markdown(f'<div class="topo-container">{svg}</div>', unsafe_allow_html=True)

    st.markdown("---")

    # ── Switch table ──
    st.markdown("### 📋 Dettaglio Switch")
    sw_data = [
        {"Switch": "S1", "Ruolo": "Core Entry",  "Slice": "Gateway H1+H2", "BW max": "—",       "Connessioni": "H1, H2, S2, S3"},
        {"Switch": "S2", "Ruolo": "Upper Relay", "Slice": "🎬 Upper",      "BW max": "10 Mbps", "Connessioni": "S1 → S4"},
        {"Switch": "S3", "Ruolo": "Lower Relay", "Slice": "📄 Lower",      "BW max": "1 Mbps",  "Connessioni": "S1 → S5"},
        {"Switch": "S4", "Ruolo": "Upper Relay", "Slice": "🎬 Upper",      "BW max": "10 Mbps", "Connessioni": "S2 → S6"},
        {"Switch": "S5", "Ruolo": "Lower Relay", "Slice": "📄 Lower",      "BW max": "1 Mbps",  "Connessioni": "S3 → S6"},
        {"Switch": "S6", "Ruolo": "Core Exit",   "Slice": "Gateway H3+H4", "BW max": "—",       "Connessioni": "S4, S5, H3, H4"},
    ]
    st.dataframe(pd.DataFrame(sw_data), use_container_width=True, hide_index=True)

    st.markdown("---")

    # ── Dynamic Slicing live ──
    st.markdown("### ⚡ Dynamic Slicing – Stato Corrente")
    d1, d2 = st.columns(2)
    d1.metric("🎬 Banda Video Stimata", f"{bw_v:.3f} Mbps",
              delta=f"< {DYNAMIC_SLICING_THRESHOLD_MBPS} → Fast Lane" if fast else
                    f"≥ {DYNAMIC_SLICING_THRESHOLD_MBPS} → Normal")
    d2.metric("📡 Percorso Dati Attivo",
              "S1→S2→S4→S6 (10 Mbps)" if fast else "S1→S3→S5→S6 (1 Mbps)")

    st.markdown(f"""
    <div class="glass-card" style="border-color:{fl_c}40;">
        <div style="font-size:1.05rem;font-weight:600;color:{fl_c};">{fl_label} — {fl_desc}</div>
        <div style="font-size:0.82rem;color:#64748b;margin-top:0.4rem;">
            Soglia di commutazione: <b>{DYNAMIC_SLICING_THRESHOLD_MBPS} Mbps</b>.
            Quando il video è inattivo i dati scalano sulla slice a 10 Mbps (Estensione 3 – Dynamic Slicing).
            Al ritorno del video la priorità torna automaticamente all'Upper Slice.
        </div>
    </div>
    """, unsafe_allow_html=True)
