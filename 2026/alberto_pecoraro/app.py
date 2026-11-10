# app.py - Entry point della dashboard SDN Slicer
# ══════════════════════════════════════════════════════════
# Avvio:  streamlit run app.py
# ══════════════════════════════════════════════════════════
import streamlit as st

from dashboard.utils import inject_css
from dashboard.pages import live_monitor, ml_analysis, topology

# ── Configurazione pagina ──
st.set_page_config(
    page_title="SDN Network Slicer",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded",
)

inject_css()

# ── Sidebar ──
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:1rem 0;">
        <div style="font-size:2.5rem;">🌐</div>
        <div style="font-size:1.1rem;font-weight:700;color:#60a5fa;">SDN Slicer</div>
        <div style="font-size:0.75rem;color:#bae6fd;margin-top:0.2rem;">Network &amp; Cloud Infrastructures</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    modulo = st.radio(
        "**Modulo**",
        options=["🔴  Live Monitor", "🧠  Analisi ML", "🗺️  Topologia"],
        label_visibility="visible",
    )

    st.markdown("---")
    st.markdown("**📡 Configurazione Rete**")
    st.markdown("""
    <div class="info-box">
    <b>Upper Slice</b><br>H1 ↔ H3 · 10 Mbps<br>S1→S2→S4→S6
    </div>
    <div class="info-box" style="border-color:rgba(99,102,241,0.35);color:#a5b4fc;background:rgba(99,102,241,0.08);">
    <b>Lower Slice</b><br>H2 ↔ H4 · 1 Mbps<br>S1→S3→S5→S6
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.caption("Mininet · Ryu · OpenFlow 1.3")

# ── Routing tra le pagine ──
if "Live" in modulo:
    live_monitor.render()
elif "ML" in modulo:
    ml_analysis.render()
elif "Topologia" in modulo:
    topology.render()
