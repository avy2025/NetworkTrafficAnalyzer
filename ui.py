import streamlit as st
import pandas as pd
import time

from monitor import NetworkMonitor
from analyzer import TrafficAnalyzer
from sniffer import PacketSniffer
from utils import CSVLogger

@st.cache_resource
def get_backend_instances():
    """Initializes globally integrated backend logic locking states cleanly bridging CSV I/O, ML Models, and Thread daemons"""
    logger = CSVLogger(log_dir="logs")
    monitor = NetworkMonitor()
    analyzer = TrafficAnalyzer(logger=logger)
    sniffer = PacketSniffer(analyzer)
    sniffer.start()
    return monitor, analyzer, sniffer, logger

def run_ui():
    st.set_page_config(page_title="Advanced Network Analyzer", layout="wide", initial_sidebar_state="expanded")
    st.title("📡 Multi-Tiered Network Traffic Analyzer")
    
    # Init cached backends hooking logic exclusively maintaining memory persistence
    monitor, analyzer, sniffer, logger = get_backend_instances()
    
    # ---------------- Sidebar Configuration & UI Controls ----------------
    st.sidebar.title("⚙️ Control Panel")
    
    is_running = st.sidebar.checkbox("🟢 Run Background Monitoring", value=True)
    if is_running:
        if sniffer.thread is None or not sniffer.thread.is_alive():
            sniffer.start()
    else:
        sniffer.stop()
        
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📥 Extract Intelligence Logs")
    
    net_log_data = logger.get_network_log_content()
    st.sidebar.download_button(
        label="Download Network Logs (CSV)",
        data=net_log_data,
        file_name="network_log.csv",
        mime="text/csv"
    )
    
    ano_log_data = logger.get_anomaly_log_content()
    st.sidebar.download_button(
        label="Download Anomaly Reports (CSV)",
        data=ano_log_data,
        file_name="anomalies.csv",
        mime="text/csv"
    )

    if not is_running:
        st.warning("⚠️ Monitoring has been gracefully shut down. All threads paused. Toggle the sidebar to resume.")
        return

    # ---------------- Phase 2: Live Network Bandwidth ----------------
    st.markdown("### Real-Time Bandwidth Extractor")
    col1, col2 = st.columns(2)

    stats = monitor.get_realtime_stats()
    up_kbps = stats["upload_speed_bps"] / 1024
    down_kbps = stats["download_speed_bps"] / 1024
    
    # Trigger active interval trace inside standard CSV Pipeline
    logger.log_network(up_kbps, down_kbps)
    
    col1.metric("Active Upload Frequency", f"{up_kbps:.2f} KB/s")
    col2.metric("Active Download Frequency", f"{down_kbps:.2f} KB/s")

    # Core Graph Implementation
    if "history_df" not in st.session_state:
        st.session_state.history_df = pd.DataFrame(columns=["Upload (KB/s)", "Download (KB/s)"])
        
    current_time = time.strftime("%H:%M:%S")
    new_data = pd.DataFrame({"Upload (KB/s)": [up_kbps], "Download (KB/s)": [down_kbps]}, index=[current_time])
    
    df = st.session_state.history_df
    df = pd.concat([df, new_data])
    if len(df) > 60:
        df = df.iloc[-60:]
    st.session_state.history_df = df
    
    st.line_chart(df)

    # ---------------- Phase 3 & 5: Analysis & Top Processes ----------------
    col3, col4 = st.columns([2, 1])
    
    with col3:
        st.markdown("### Targeted Device Process Maps")
        st.markdown("*Note: Approximation logic tracking Process Disk I/O bindings*")
        process_stats = monitor.get_process_network_usage()
        if process_stats:
            proc_df = pd.DataFrame([{
                "PID": p["pid"],
                "Process Name": p["name"],
                "Upload (KB/s)": round(p["upload_speed_bps"] / 1024, 2),
                "Download (KB/s)": round(p["download_speed_bps"] / 1024, 2),
                "Total (KB/s)": round(p["total_speed_bps"] / 1024, 2)
            } for p in process_stats])
        else:
            proc_df = pd.DataFrame(columns=["PID", "Process Name", "Upload (KB/s)", "Download (KB/s)", "Total (KB/s)"])
        st.dataframe(proc_df, use_container_width=True, hide_index=True)
        
    with col4:
        st.markdown("### System Alert Log")
        insights = analyzer.extract_insights()
        
        if insights["anomalies"]:
            alert_html = "<div style='height:280px; overflow-y:auto; padding:10px; border:2px solid #ff4b4b; border-radius:5px; background-color: #2b1111;'>"
            for alert in insights["anomalies"]:
                alert_html += f"<p style='color:#ff4b4b; font-family: monospace;'>🛡️ {alert}</p>"
            alert_html += "</div>"
            st.markdown(alert_html, unsafe_allow_html=True)
        else:
            st.info("Traffic Baseline Secure. Listening...", icon="📡")
        
    st.markdown("### Phase 5 Deep Diagnostics")
    col5, col6 = st.columns(2)
    
    with col5:
        st.markdown("#### Primary Top 5 IP Traffic Sources")
        if insights["top_ips"]:
            ip_df = pd.DataFrame([{"Node IP Address": x["ip"], "Bytes Intercepted": x["bytes"]} for x in insights["top_ips"]])
            st.dataframe(ip_df, use_container_width=True, hide_index=True)
        else:
            st.warning("Packet queue indexing...")
            
    with col6:
        st.markdown("#### Foundational Protocol Usage Bytes")
        if insights["top_protocols"]:
            proto_df = pd.DataFrame([{"Data Protocol Class": x["protocol"], "Processed Traffic Count (Bytes)": x["bytes"]} for x in insights["top_protocols"]])
            st.dataframe(proto_df, use_container_width=True, hide_index=True)
        else:
            st.warning("Protocol queue indexing...")

    # Safely lock the active thread cycle waiting 1s before seamlessly reloading the UI context layout resolving Interactive freezes
    time.sleep(1)
    st.rerun()

if __name__ == "__main__":
    run_ui()
