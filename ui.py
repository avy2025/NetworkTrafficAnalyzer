import streamlit as st
import pandas as pd
import time

from monitor import NetworkMonitor
from analyzer import TrafficAnalyzer
from sniffer import PacketSniffer

# Critical to freeze state locally across interface loads to protect system level Background daemon loops
@st.cache_resource
def get_backend_instances():
    """Initializes strictly one instance of threaded infrastructure across all UI ticks."""
    monitor = NetworkMonitor()
    analyzer = TrafficAnalyzer()
    sniffer = PacketSniffer(analyzer)
    sniffer.start()
    return monitor, analyzer, sniffer


def run_ui():
    st.set_page_config(page_title="Network Traffic Analyzer", layout="wide")
    st.title("📡 Next-Gen Network Traffic Analyzer")
    
    monitor, analyzer, sniffer = get_backend_instances()
    
    # --- Structural Layouts ---
    st.markdown("### Real-Time Pipeline")
    col1, col2 = st.columns(2)
    upload_metric = col1.empty()
    download_metric = col2.empty()

    st.markdown("### Total Bandwidth Topology")
    chart_placeholder = st.empty()

    # --- Insight Topology ---
    col3, col4 = st.columns([2, 1])
    
    with col3:
        st.markdown("### Targeted Device Process Maps")
        st.markdown("*Note: Native Scapy mapping hooks incoming in later phases*")
        process_table_placeholder = st.empty()
        
    with col4:
        st.markdown("### System Alert Log")
        anomaly_placeholder = st.empty()
        
    st.markdown("### Phase 5 Deep Diagnostics")
    col5, col6 = st.columns(2)
    
    with col5:
        st.markdown("#### Primary Top 5 IP Traffic Sources")
        ip_placeholder = st.empty()
        
    with col6:
        st.markdown("#### Foundational Protocol Usage Bytes")
        proto_placeholder = st.empty()

    if "history_df" not in st.session_state:
        st.session_state.history_df = pd.DataFrame(columns=["Upload (KB/s)", "Download (KB/s)"])
    
    try:
        while True:
            # Data pipelines
            stats = monitor.get_realtime_stats()
            process_stats = monitor.get_process_network_usage()
            
            up_kbps = stats["upload_speed_bps"] / 1024
            down_kbps = stats["download_speed_bps"] / 1024
            
            upload_metric.metric("Active Upload Frequency", f"{up_kbps:.2f} KB/s")
            download_metric.metric("Active Download Frequency", f"{down_kbps:.2f} KB/s")
            
            # Visuals pipelines
            current_time = time.strftime("%H:%M:%S")
            new_data = pd.DataFrame(
                {"Upload (KB/s)": [up_kbps], "Download (KB/s)": [down_kbps]},
                index=[current_time]
            )
            
            df = st.session_state.history_df
            df = pd.concat([df, new_data])
            if len(df) > 60:
                df = df.iloc[-60:]
            st.session_state.history_df = df
            chart_placeholder.line_chart(df)
            
            # DataFrame pipelines
            if process_stats:
                formatted_stats = [{
                    "PID": p["pid"],
                    "Process Name": p["name"],
                    "Upload (KB/s)": round(p["upload_speed_bps"] / 1024, 2),
                    "Download (KB/s)": round(p["download_speed_bps"] / 1024, 2),
                    "Total (KB/s)": round(p["total_speed_bps"] / 1024, 2)
                } for p in process_stats]
                proc_df = pd.DataFrame(formatted_stats)
            else:
                proc_df = pd.DataFrame(columns=["PID", "Process Name", "Upload (KB/s)", "Download (KB/s)", "Total (KB/s)"])
            process_table_placeholder.dataframe(proc_df, use_container_width=True, hide_index=True)
            
            
            # --- Phase 5 API Call ---
            insights = analyzer.extract_insights()
            
            # Display Alert Engine
            if insights["anomalies"]:
                alert_html = "<div style='height:280px; overflow-y:auto; padding:10px; border:2px solid #ff4b4b; border-radius:5px; background-color: #2b1111;'>"
                for alert in insights["anomalies"]:
                    alert_html += f"<p style='color:#ff4b4b; font-family: monospace;'>🛡️ {alert}</p>"
                alert_html += "</div>"
                anomaly_placeholder.markdown(alert_html, unsafe_allow_html=True)
            else:
                anomaly_placeholder.info("Traffic Baseline Secure. Listening...", icon="📡")
                
            # Display Dominating Addresses
            if insights["top_ips"]:
                ip_df = pd.DataFrame([{"Node IP Address": x["ip"], "Bytes Intercepted": x["bytes"]} for x in insights["top_ips"]])
                ip_placeholder.dataframe(ip_df, use_container_width=True, hide_index=True)
            else:
                ip_placeholder.warning("Packet queue indexing...")
                
            # Display Active Protocols
            if insights["top_protocols"]:
                proto_df = pd.DataFrame([{"Data Protocol Class": x["protocol"], "Processed Traffic Count (Bytes)": x["bytes"]} for x in insights["top_protocols"]])
                proto_placeholder.dataframe(proto_df, use_container_width=True, hide_index=True)
            else:
                proto_placeholder.warning("Protocol queue indexing...")
            
            time.sleep(1)
            
    except Exception as e:
         st.error(f"Framework stopped or an unexpected system error occurred: {e}")

if __name__ == "__main__":
    run_ui()
