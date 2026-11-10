import os
import pandas as pd
import streamlit as st
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

# ==========================================
# COSTANTI
# ==========================================
# Il CSV viene salvato da Ryu nella root del progetto (livello superiore rispetto a /dashboard)
CSV_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "traffic_data.csv")

MAC_NAMES = {
    '00:00:00:00:00:01': 'H1',
    '00:00:00:00:00:02': 'H2',
    '00:00:00:00:00:03': 'H3',
    '00:00:00:00:00:04': 'H4',
}

UPPER_SLICE = {'src': '00:00:00:00:00:01', 'dst': '00:00:00:00:00:03'}
LOWER_SLICE = {'src': '00:00:00:00:00:02', 'dst': '00:00:00:00:00:04'}

DYNAMIC_SLICING_THRESHOLD_MBPS = 0.5

COLOR_UPPER  = '#f59e0b'
COLOR_LOWER  = '#6366f1'
COLOR_FAST   = '#34d399'
COLOR_SLOW   = '#f87171'
COLOR_ACCENT = '#60a5fa'
COLOR_RYU    = '#38bdf8'

# ==========================================
# STILE CSS
# ==========================================
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif; color: #f1f5f9; }
.stApp { background: linear-gradient(135deg, #0a0e1a 0%, #0d1421 50%, #0a1628 100%); min-height: 100vh; }
[data-testid="stSidebar"] { background: linear-gradient(180deg, #0d1421 0%, #111827 100%); border-right: 1px solid rgba(99,179,237,0.15); }
[data-testid="stSidebar"] .stRadio label { color: #f8fafc !important; font-size: 0.95rem; font-weight: 500; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color: #f8fafc !important; }
[data-testid="stSidebar"] [data-testid="stCaptionContainer"] p { color: #bae6fd !important; font-size: 0.8rem; }
h1, h2, h3 { color: #e2e8f0 !important; }
.hero-header { background: linear-gradient(135deg, rgba(14,165,233,0.15) 0%, rgba(139,92,246,0.10) 50%, rgba(6,182,212,0.15) 100%); border: 1px solid rgba(99,179,237,0.25); border-radius: 20px; padding: 2rem 2.5rem; margin-bottom: 2rem; overflow: hidden; }
.hero-title { font-size: 2.2rem; font-weight: 700; background: linear-gradient(90deg, #60a5fa, #a78bfa, #34d399); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; margin: 0; }
.hero-subtitle { color: #94a3b8; font-size: 0.95rem; margin-top: 0.5rem; }
.badge-live { display: inline-flex; align-items: center; gap: 6px; background: rgba(239,68,68,0.15); border: 1px solid rgba(239,68,68,0.4); color: #f87171; padding: 4px 12px; border-radius: 20px; font-size: 0.78rem; font-weight: 600; letter-spacing: 0.05em; margin-top: 0.8rem; }
.badge-live::before { content: ''; width: 8px; height: 8px; background: #ef4444; border-radius: 50%; animation: blink 1.2s ease-in-out infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.2} }
.glass-card { background: rgba(255,255,255,0.04); border: 1px solid rgba(99,179,237,0.18); border-radius: 16px; padding: 1.5rem; backdrop-filter: blur(10px); margin-bottom: 1rem; box-shadow: 0 4px 30px rgba(0,0,0,0.3); transition: all 0.3s ease; }
.glass-card:hover { border-color: rgba(99,179,237,0.4); box-shadow: 0 8px 40px rgba(99,179,237,0.1); transform: translateY(-2px); }
.slice-upper { border-left: 4px solid #f59e0b; padding-left: 1rem; }
.slice-lower { border-left: 4px solid #6366f1; padding-left: 1rem; }
.info-box { background: rgba(14,165,233,0.08); border: 1px solid rgba(14,165,233,0.25); border-radius: 10px; padding: 1rem 1.2rem; color: #93c5fd; font-size: 0.88rem; margin: 0.5rem 0; }
[data-testid="stMetric"] { background: rgba(255,255,255,0.03) !important; border: 1px solid rgba(99,179,237,0.15) !important; border-radius: 12px !important; padding: 1rem !important; }
[data-testid="stMetricValue"]  { color: #60a5fa !important; font-family: 'JetBrains Mono', monospace !important; }
[data-testid="stMetricLabel"]  { color: #94a3b8 !important; }
.stButton > button { background: linear-gradient(135deg, #1d4ed8, #6d28d9) !important; color: white !important; border: none !important; border-radius: 10px !important; font-weight: 600 !important; transition: all 0.3s ease !important; }
.stButton > button:hover { transform: translateY(-1px) !important; box-shadow: 0 6px 20px rgba(109,40,217,0.4) !important; }
.topo-container { background: rgba(0,0,0,0.3); border: 1px solid rgba(99,179,237,0.15); border-radius: 16px; padding: 1.5rem; text-align: center; }
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #0d1421; }
::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #475569; }
</style>
"""

def inject_css():
    st.markdown(CSS, unsafe_allow_html=True)

# ==========================================
# FUNZIONI DI UTILITÀ
# ==========================================
def load_csv():
    if not os.path.exists(CSV_FILE):
        return None, f"File non trovato: `{CSV_FILE}`"
    try:
        df = pd.read_csv(CSV_FILE).dropna()
        if df.empty:
            return None, "Il file CSV è vuoto. Avvia il traffico di rete."
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['mb_count']  = df['byte_count'] / 1_000_000
        df['src_name']  = df['src'].map(MAC_NAMES).fillna(df['src'])
        df['dst_name']  = df['dst'].map(MAC_NAMES).fillna(df['dst'])
        return df, None
    except Exception as exc:
        return None, f"Errore nella lettura del CSV: {exc}"

def classify_l1(row):
    s, d = row.get('src', ''), row.get('dst', '')
    if {s, d} == {'00:00:00:00:00:01', '00:00:00:00:00:03'}:
        return 'Video (Upper Slice)'
    if {s, d} == {'00:00:00:00:00:02', '00:00:00:00:00:04'}:
        return 'Dati (Lower Slice)'
    return 'Altro'

def classify_l2_ml(df):
    df = df.copy()
    if len(df) < 4:
        df['Cluster_ID'] = -1
        df['ML_Class']   = 'Dati insufficienti'
        return df

    X = df[['packet_count', 'byte_count']]
    X_scaled = StandardScaler().fit_transform(X)

    kmeans = KMeans(n_clusters=2, random_state=42, n_init=10)
    df['Cluster_ID'] = kmeans.fit_predict(X_scaled)

    video_cluster = int(df.groupby('Cluster_ID')['byte_count'].mean().idxmax())
    df['ML_Class'] = df['Cluster_ID'].map({
        video_cluster:     '🎬 Alta Banda (Video)',
        1 - video_cluster: '📄 Bassa Banda (Dati)',
    })
    return df

def calc_bw_mbps(flow_df, window=6):
    if len(flow_df) < 2:
        return 0.0
    tail = flow_df.tail(window).sort_values('timestamp')
    byte_diff = tail['byte_count'].diff().dropna()
    time_s = tail['timestamp'].diff().dt.total_seconds().dropna()
    valid = time_s[time_s > 0]
    if valid.empty:
        return 0.0
    bw = (byte_diff[valid.index] * 8 / valid) / 1_000_000
    return max(float(bw.mean()), 0.0)

def is_fast_lane_active(bw_video_mbps):
    return bw_video_mbps < DYNAMIC_SLICING_THRESHOLD_MBPS
