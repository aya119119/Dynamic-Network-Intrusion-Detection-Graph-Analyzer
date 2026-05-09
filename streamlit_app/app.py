import streamlit as st
import pandas as pd
import networkx as nx
import plotly.graph_objects as go
import plotly.express as px
import os
import sys
import time
from pathlib import Path
from pyvis.network import Network
import streamlit.components.v1 as components

# Add parent directory to path to import src modules
# Get the project root (parent of streamlit_app folder)
app_dir = Path(__file__).parent  # streamlit_app folder
project_root = app_dir.parent     # project root
sys.path.insert(0, str(project_root))

# Define data and output paths
DATA_PATH = project_root / "data" / "network_traffic_data.csv"
OUTPUT_PATH = project_root / "output" / "threat_alerts.csv"

# Create output directory if it doesn't exist
OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

from src.graph_builder import build_graph, get_graph_statistics
from src.intrusion_detection_engine import run_intrusion_detection


# Configure page
st.set_page_config(
    page_title="DINDGA Security Command Center", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load CSS
def local_css(file_name):
    if os.path.exists(file_name):
        with open(file_name) as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

local_css("streamlit_app/style.css")

# --- UI HEADER ---
st.markdown("""
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem;">
        <div>
            <h1 style="margin: 0; color: #00d4ff; font-weight: 800; letter-spacing: -1px;">🛡️ DINDGA</h1>
            <p style="margin: 0; color: #8b949e; font-size: 1.1rem;">Dynamic Network Intrusion Detection Graph Analyzer</p>
        </div>
        <div style="text-align: right;">
            <div style="background: rgba(0, 212, 255, 0.1); border: 1px solid #00d4ff; padding: 5px 15px; border-radius: 20px; color: #00d4ff; font-weight: 600;">
                SYSTEM STATUS: ACTIVE
            </div>
            <p style="margin: 5px 0 0 0; color: #8b949e; font-size: 0.8rem;">V2.0.0 - Premium Edition</p>
        </div>
    </div>
""", unsafe_allow_html=True)

# Load data and run detection
@st.cache_data
def load_and_process_data():
    csv_path = str(DATA_PATH)
    output_path = str(OUTPUT_PATH)
    
    if not os.path.exists(csv_path):
        st.error(f"❌ Data file not found at: {csv_path}")
        st.info("📂 Expected location: `data/network_traffic_data.csv` in the repository root")
        return None, None, None, None
    
    try:
        # Run the full intrusion detection pipeline to get all data
        final_df, alerts_df = run_intrusion_detection(csv_path=csv_path, output_path=output_path)
        
        # Load raw data for overview
        raw_df = pd.read_csv(csv_path)
        
        # Build graph for visualization
        G = build_graph(raw_df)
        
        return raw_df, G, final_df, alerts_df
    except Exception as e:
        st.error(f"⚠️ Error processing data: {str(e)}")
        return None, None, None, None

with st.spinner("Initializing DINDGA Intelligence Engine..."):
    raw_df, G, final_df, alerts_df = load_and_process_data()

if raw_df is None:
    st.error("Missing Data Source: `network_traffic_data.csv` not found.")
    st.stop()

# --- SIDEBAR ---
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=80)
    st.title("Control Panel")
    
    st.subheader("Global Filters")
    # Label Filter
    available_labels = ["All"] + list(raw_df['Label'].unique()) if 'Label' in raw_df.columns else ["All"]
    selected_label = st.selectbox("Traffic Type Filter", available_labels)

    # Timeline Slider
    if 'Timestamp' in raw_df.columns:
        raw_df['Timestamp'] = pd.to_datetime(raw_df['Timestamp'])
        min_time = raw_df['Timestamp'].min()
        max_time = raw_df['Timestamp'].max()
        
        time_range = st.slider(
            "Observation Window",
            value=(min_time.to_pydatetime(), max_time.to_pydatetime()),
            format="HH:mm:ss"
        )
    else:
        time_range = None

    st.markdown("---")
    st.subheader("Detection Sensitivity")
    min_threat = st.slider("Threat Threshold", 0.0, 1.0, 0.4)
    
    st.markdown("---")
    simulation_mode = st.toggle("Live Monitoring Simulation 📡", value=False)

# Apply filters
filtered_raw_df = raw_df.copy()
if selected_label != "All":
    filtered_raw_df = filtered_raw_df[filtered_raw_df['Label'] == selected_label]
if time_range is not None:
    filtered_raw_df = filtered_raw_df[
        (filtered_raw_df['Timestamp'] >= pd.to_datetime(time_range[0])) &
        (filtered_raw_df['Timestamp'] <= pd.to_datetime(time_range[1]))
    ]

# Rebuild graph dynamically
G_filtered = build_graph(filtered_raw_df) if not filtered_raw_df.empty else nx.Graph()

# --- MAIN TABS ---
tab1, tab2, tab3, tab4 = st.tabs([
    "🚀 Executive Summary", 
    "🕸️ Network Topology", 
    "🔍 Threat Analysis", 
    "📑 Reports & Logs"
])

with tab1:
    # Key Metrics
    col1, col2, col3, col4 = st.columns(4)
    stats = get_graph_statistics(G_filtered)
    
    col1.metric("Active IPs", f"{stats['num_nodes']:,}", "Network Nodes")
    col2.metric("Connections", f"{stats['num_edges']:,}", "Active Edges")
    
    high_threats = len(final_df[final_df['threat_score'] >= 0.7])
    col3.metric("High Threats", f"{high_threats}", f"{high_threats/len(final_df)*100:.1f}% of IPs", delta_color="inverse")
    
    total_vol = filtered_raw_df['BytesSent'].sum() + filtered_raw_df['BytesReceived'].sum() if 'BytesSent' in filtered_raw_df.columns else 0
    col4.metric("Data Volume", f"{total_vol/1e6:.2f} MB", "Traffic Flow")

    st.markdown("### 📈 Real-time Traffic Distribution")
    if 'Timestamp' in filtered_raw_df.columns:
        traffic_over_time = filtered_raw_df.set_index('Timestamp').resample('1min').size().reset_index(name='packets')
        fig_traffic = px.area(traffic_over_time, x='Timestamp', y='packets', 
                             color_discrete_sequence=['#00d4ff'],
                             template="plotly_dark")
        fig_traffic.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis_title="",
            yaxis_title="Packet Count",
            margin=dict(l=0, r=0, t=20, b=0),
            height=300
        )
        st.plotly_chart(fig_traffic, use_container_width=True)

    # Simulation Mode
    if simulation_mode:
        st.info("Simulation Mode Active: Streaming filtered traffic data...")
        progress_bar = st.progress(0)
        status_text = st.empty()
        for percent_complete in range(100):
            time.sleep(0.01)
            progress_bar.progress(percent_complete + 1)
            status_text.text(f"Analysing packets... {percent_complete+1}%")
        st.success("Analysis Complete.")

with tab2:
    st.markdown("### 🕸️ Interactive Topology Explorer")
    st.markdown("Click and drag nodes to explore. Colors indicate **Threat Level**.")
    
    # Pyvis Integration
    nt = Network(height="600px", width="100%", bgcolor="#0e1117", font_color="white", notebook=False)
    
    for node in G_filtered.nodes():
        threat = final_df.loc[node, 'threat_score'] if node in final_df.index else 0.0
        # Color mapping: Green to Yellow to Red
        if threat >= 0.7: color = "#ff4b4b" # Red
        elif threat >= 0.4: color = "#ffa500" # Orange
        else: color = "#00d4ff" # Cyan
        
        size = 15 + (threat * 20)
        label = f"{node}\nScore: {threat:.2f}"
        nt.add_node(node, label=label, color=color, size=size, title=f"IP: {node}\nThreat: {threat:.3f}")

    for edge in G_filtered.edges():
        nt.add_edge(edge[0], edge[1], color="#444", width=1)

    nt.toggle_physics(True)
    nt.set_options("""
    var options = {
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -50,
          "centralGravity": 0.01,
          "springLength": 100,
          "springConstant": 0.08
        },
        "maxVelocity": 50,
        "solver": "forceAtlas2Based",
        "timestep": 0.35,
        "stabilization": { "iterations": 150 }
      }
    }
    """)
    
    # Save and read
    nt.save_graph("network.html")
    with open("network.html", 'r', encoding='utf-8') as f:
        html_data = f.read()
    
    components.html(html_data, height=650)

with tab3:
    col_a, col_b = st.columns([2, 1])
    
    with col_a:
        st.markdown("### 🔍 Suspicious Behavior Investigation")
        filtered_results = final_df[final_df['threat_score'] >= min_threat]
        st.dataframe(
            filtered_results.style.background_gradient(subset=['threat_score'], cmap='YlOrRd'),
            use_container_width=True
        )

    with col_b:
        st.markdown("### 📊 Threat Statistics")
        threat_dist = px.histogram(final_df, x="threat_score", nbins=20, 
                                 title="Threat Score Distribution",
                                 color_discrete_sequence=['#ff4b4b'],
                                 template="plotly_dark")
        st.plotly_chart(threat_dist, use_container_width=True)
        
        # Pie chart of threat levels
        level_counts = final_df['threat_level'].value_counts().reset_index()
        fig_pie = px.pie(level_counts, values='count', names='threat_level', 
                        color='threat_level',
                        color_discrete_map={'High': '#ff4b4b', 'Medium': '#ffa500', 'Low': '#00d4ff'},
                        title="Network Risk Composition",
                        template="plotly_dark")
        st.plotly_chart(fig_pie, use_container_width=True)

with tab4:
    st.markdown("### 🚨 Security Alerts Feed")
    if alerts_df.empty:
        st.success("No critical alerts generated for current filters.")
    else:
        for _, alert in alerts_df.iterrows():
            st.markdown(f"""
                <div class="threat-alert">
                    <strong style="color: #ff4b4b;">[{alert['threat_level']}]</strong> IP: {alert['ip']} <br>
                    <span style="color: #8b949e;">Reason: {alert['reason']}</span> | 
                    <span style="color: #00d4ff;">Score: {alert['threat_score']}</span>
                </div>
            """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 📁 Export Data")
    c1, c2 = st.columns(2)
    
    csv_full = final_df.to_csv().encode('utf-8')
    c1.download_button("Download Detection Results (CSV)", csv_full, "dindga_results.csv", "text/csv")
    
    csv_alerts = alerts_df.to_csv().encode('utf-8')
    c2.download_button("Download High-Risk Alerts (CSV)", csv_alerts, "dindga_alerts.csv", "text/csv")

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #8b949e;'>DINDGA © 2026 | Built for Advanced Network Security Analysis</div>", 
    unsafe_allow_html=True
)
