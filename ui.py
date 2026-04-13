import streamlit as st
import pandas as pd
import time
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime

from monitor import NetworkMonitor
from analyzer import TrafficAnalyzer
from sniffer import PacketSniffer
from utils import CSVLogger

# ----------------- Premium CSS Injection -----------------
CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@400;600;700&display=swap');

    /* Global Styles */
    html, body, [data-testid="stAppViewContainer"] {
        font-family: 'Inter', sans-serif;
        background-color: #0e1117;
        color: #fafafa;
    }

    [data-testid="stHeader"] {
        background: rgba(14, 17, 23, 0.8);
        backdrop-filter: blur(10px);
    }

    /* Sidebar styling */
    section[data-testid="stSidebar"] {
        background-color: #0b0d12 !important;
        border-right: 1px solid rgba(255, 255, 255, 0.05);
    }

    /* Dashboard Cards */
    .dashboard-card {
        background: rgba(255, 255, 255, 0.02);
        border-radius: 12px;
        padding: 24px;
        border: 1px solid rgba(255, 255, 255, 0.05);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        margin-bottom: 20px;
    }

    /* Titles and Headers */
    .main-title {
        font-family: 'Outfit', sans-serif;
        font-weight: 700;
        font-size: 2.8rem;
        background: linear-gradient(90deg, #00f2fe 0%, #4facfe 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.5rem;
    }

    .sub-title {
        font-family: 'Inter', sans-serif;
        font-size: 1rem;
        color: #888;
        margin-bottom: 2rem;
    }

    .section-header {
        font-family: 'Outfit', sans-serif;
        font-weight: 600;
        font-size: 1.4rem;
        margin-bottom: 1rem;
        color: #fafafa;
        display: flex;
        align-items: center;
        gap: 10px;
    }

    /* Metrics Styling */
    [data-testid="stMetricValue"] {
        font-family: 'Outfit', sans-serif;
        font-weight: 700;
        color: #00f2fe !important;
    }

    /* Alert Dashboard */
    .alert-container {
        height: 420px;
        overflow-y: auto;
        padding: 5px;
        background-color: transparent;
    }

    .alert-card {
        background: rgba(255, 255, 255, 0.03);
        border-radius: 8px;
        padding: 12px;
        margin-bottom: 10px;
        border-left: 4px solid #ff4b4b;
        transition: transform 0.2s ease;
    }

    .alert-card:hover {
        transform: translateX(5px);
        background: rgba(255, 255, 255, 0.05);
    }

    .severity-high { border-left-color: #ff4b4b; }
    .severity-critical { border-left-color: #ff0000; box-shadow: 0 0 15px rgba(255, 0, 0, 0.1); }
    .severity-medium { border-left-color: #ffa500; }
    .severity-low { border-left-color: #ffff00; }

    .alert-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 5px;
    }

    .alert-type {
        font-weight: 700;
        font-size: 0.9rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .alert-time {
        font-size: 0.75rem;
        color: #888;
    }

    .alert-desc {
        font-size: 0.85rem;
        color: #ddd;
        line-height: 1.4;
    }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 5px; }
    ::-webkit-scrollbar-track { background: #0e1117; }
    ::-webkit-scrollbar-thumb { background: #333; border-radius: 10px; }
    ::-webkit-scrollbar-thumb:hover { background: #444; }

    /* Hide standard streamlit elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
</style>
"""

@st.cache_resource
def get_backend_instances():
    """
    Initializes and caches the network monitoring backend components.
    Connects the monitor, analyzer, sniffer, and logger into a unified pipeline.
    """
    logger = CSVLogger(log_dir="logs")
    monitor = NetworkMonitor()
    analyzer = TrafficAnalyzer(logger=logger)
    sniffer = PacketSniffer(analyzer)
    sniffer.start()
    return monitor, analyzer, sniffer, logger

def run_ui():
    """
    Main entry point for the Streamlit dashboard.
    Manages the live metrics update loop and user interactions.
    """
    st.set_page_config(
        page_title="Network Sentinel | Advanced Analyzer",
        page_icon="📡",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    st.markdown(CSS, unsafe_allow_html=True)
    
    # Init cached backends
    monitor, analyzer, sniffer, logger = get_backend_instances()
    
    # ---------------- Sidebar Configuration ----------------
    with st.sidebar:
        st.markdown("<h2 style='font-family:Outfit; font-weight:700;'>⚙️ Control Center</h2>", unsafe_allow_html=True)
        
        is_running = st.checkbox("Active Monitoring Thread", value=True)
        if is_running:
            if sniffer.thread is None or not sniffer.thread.is_alive():
                sniffer.start()
            st.success("System Live", icon="🟢")
        else:
            sniffer.stop()
            st.warning("Systems Paused", icon="🟡")
            
        st.markdown("---")
        st.markdown("### 📥 Telemetry Export")
        
        net_log_data = logger.get_network_log_content()
        st.download_button(
            label="Download Traffic Data (CSV)",
            data=net_log_data,
            file_name=f"network_telemetry_{int(time.time())}.csv",
            mime="text/csv",
            use_container_width=True
        )
        
        ano_log_data = logger.get_anomaly_log_content()
        st.download_button(
            label="Download Incident Reports",
            data=ano_log_data,
            file_name=f"security_incidents_{int(time.time())}.csv",
            mime="text/csv",
            use_container_width=True
        )

        st.markdown("---")
        st.info("Network Sentinel v2.0 - Advanced Traffic Intelligence Dashboard")

    if not is_running:
        st.markdown("<div class='dashboard-card'>", unsafe_allow_html=True)
        st.title("🛡️ Network Sentinel")
        st.error("Monitoring is currently offline. Please toggle the 'Active Monitoring Thread' in the control panel to resume data ingestion.")
        st.markdown("</div>", unsafe_allow_html=True)
        return

    # ---------------- Header ----------------
    st.markdown("<div class='main-title'>📡 Network Sentinel</div>", unsafe_allow_html=True)
    st.markdown("<div class='sub-title'>Precision Traffic Intelligence & Real-Time Anomaly Detection Engine</div>", unsafe_allow_html=True)

    # ---------------- Phase 2: Live Metrics ----------------
    stats = monitor.get_realtime_stats()
    up_kbps = stats["upload_speed_bps"] / 1024
    down_kbps = stats["download_speed_bps"] / 1024
    logger.log_network(up_kbps, down_kbps)

    # Manage Peak Speeds
    if "peak_up" not in st.session_state:
        st.session_state.peak_up = 0.0
    if "peak_down" not in st.session_state:
        st.session_state.peak_down = 0.0
        
    st.session_state.peak_up = max(st.session_state.peak_up, up_kbps)
    st.session_state.peak_down = max(st.session_state.peak_down, down_kbps)

    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    
    with m_col1:
        st.metric("Upload Speed", f"{up_kbps:.1f} KB/s", delta=f"{up_kbps - st.session_state.peak_up:.1f} (Peak)")
    with m_col2:
        st.metric("Download Speed", f"{down_kbps:.1f} KB/s", delta=f"{down_kbps - st.session_state.peak_down:.1f} (Peak)")
    with m_col3:
        st.metric("Peak Upload", f"{st.session_state.peak_up:.1f} KB/s")
    with m_col4:
        st.metric("Peak Download", f"{st.session_state.peak_down:.1f} KB/s")

    st.markdown("---")

    # ---------------- Main Dashboard Layout ----------------
    row1_col1, row1_col2 = st.columns([2, 1])

    with row1_col1:
        st.markdown("<div class='section-header'>📊 Bandwidth Throughput Analysis</div>", unsafe_allow_html=True)
        
        # Bandwidth History Management
        if "history_df" not in st.session_state:
            st.session_state.history_df = pd.DataFrame(columns=["Upload", "Download", "Time"])
            
        current_time = datetime.now().strftime("%H:%M:%S")
        new_row = pd.DataFrame({"Upload": [up_kbps], "Download": [down_kbps], "Time": [current_time]})
        
        df = st.session_state.history_df
        df = pd.concat([df, new_row])
        if len(df) > 50:
            df = df.iloc[-50:]
        st.session_state.history_df = df

        # Plotly Area Chart
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df["Time"], y=df["Download"],
            name="Download", fill='tozeroy',
            line=dict(color='#4facfe', width=2),
            fillcolor='rgba(79, 172, 254, 0.2)'
        ))
        fig.add_trace(go.Scatter(
            x=df["Time"], y=df["Upload"],
            name="Upload", fill='tozeroy',
            line=dict(color='#00f2fe', width=2),
            fillcolor='rgba(0, 242, 254, 0.2)'
        ))
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            margin=dict(l=0, r=0, t=20, b=0),
            height=350,
            hovermode='x unified',
            xaxis=dict(showgrid=False, color='#888'),
            yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.05)', color='#888'),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

    with row1_col2:
        st.markdown("<div class='section-header'>🛡️ Intelligence Incident Log</div>", unsafe_allow_html=True)
        insights = analyzer.extract_insights()
        
        if insights["anomalies"]:
            alert_html = "<div class='alert-container'>"
            for alert in insights["anomalies"]:
                severity_class = f"severity-{alert['severity'].lower()}"
                icon = "🚨" if alert['severity'] == "Critical" else "⚠️"
                alert_html += f"""
                <div class='alert-card {severity_class}'>
                    <div class='alert-header'>
                        <span class='alert-type'>{icon} {alert['type']}</span>
                        <span class='alert-time'>{alert['timestamp']}</span>
                    </div>
                    <div class='alert-desc'>{alert['description']}</div>
                </div>
                """
            alert_html += "</div>"
            st.markdown(alert_html, unsafe_allow_html=True)
        else:
            st.markdown(
                "<div class='alert-container' style='display:flex; align-items:center; justify-content:center; flex-direction:column; color:#888;'>"
                "<div style='font-size:3rem; margin-bottom:10px;'>📡</div>"
                "<div>Listening for Traffic Irregularities...</div>"
                "<div style='font-size:0.8rem; margin-top:5px; opacity:0.6;'>Monitoring patterns for spikes and floods</div>"
                "</div>", 
                unsafe_allow_html=True
            )

    # ---------------- Row 2: Deep Analysis ----------------
    row2_col1, row2_col2 = st.columns([3, 2])

    with row2_col1:
        st.markdown("<div class='section-header'>🚀 High-Activity Process Map</div>", unsafe_allow_html=True)
        process_stats = monitor.get_process_network_usage()
        if process_stats:
            proc_df = pd.DataFrame([{
                "Application": p["name"],
                "Up (KB/s)": round(p["upload_speed_bps"] / 1024, 1),
                "Down (KB/s)": round(p["download_speed_bps"] / 1024, 1),
                "Total Intensity": round(p["total_speed_bps"] / 1024, 1)
            } for p in process_stats])
            st.dataframe(proc_df, use_container_width=True, hide_index=True)
        else:
            st.info("Aggregating process I/O bindings...")

    with row2_col2:
        st.markdown("<div class='section-header'>🌐 Protocol Extraction Ratio</div>", unsafe_allow_html=True)
        if insights["top_protocols"]:
            proto_df = pd.DataFrame(insights["top_protocols"])
            fig_pie = px.pie(
                proto_df, values='bytes', names='protocol',
                color_discrete_sequence=px.colors.sequential.Cyan_r,
                hole=0.4
            )
            fig_pie.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=0, r=0, t=0, b=0),
                height=300,
                showlegend=True,
                legend=dict(font=dict(color="#888"))
            )
            st.plotly_chart(fig_pie, use_container_width=True, config={'displayModeBar': False})
        else:
            st.warning("Sampling packet stream for protocol classification...")

    # ---------------- Row 3: Target Intelligence ----------------
    st.markdown("<div class='section-header'>📍 Top Traffic Destination Nodes (IP)</div>", unsafe_allow_html=True)
    if insights["top_ips"]:
        ip_df = pd.DataFrame([{"Node IP Address": x["ip"], "Bytes Intercepted": x["bytes"], "Percentage": f"{(x['bytes']/sum(i['bytes'] for i in insights['top_ips'])*100):.1f}%"} for x in insights["top_ips"]])
        st.dataframe(ip_df, use_container_width=True, hide_index=True)
    else:
        st.info("Indexing IP frequency tables...")

    # Cycle wait & reload
    time.sleep(1)
    st.rerun()

if __name__ == "__main__":
    run_ui()

