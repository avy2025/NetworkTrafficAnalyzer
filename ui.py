import streamlit as st
import pandas as pd
import time
from monitor import NetworkMonitor

def run_ui():
    st.set_page_config(page_title="Network Traffic Analyzer", layout="wide")
    st.title("📡 Network Traffic Analyzer")
    st.markdown("### Real-Time Bandwidth UI")

    # Metrics Layout
    col1, col2 = st.columns(2)
    upload_metric = col1.empty()
    download_metric = col2.empty()

    st.markdown("### Bandwidth Over Time")
    chart_placeholder = st.empty()

    # Process table layout
    st.markdown("### Top 10 Processes by Network Usage")
    st.markdown("*Approximation: Uses combined IO for networked processes. To be upgraded with Sniffer in Phase 4.*")
    table_placeholder = st.empty()

    # Initialize the monitor component
    monitor = NetworkMonitor()
    
    # Initialize dataframe for chart history
    df = pd.DataFrame(columns=["Upload (KB/s)", "Download (KB/s)"])
    
    try:
        while True:
            # Fetch real-time data from Phase 1/Phase 3 monitor
            stats = monitor.get_realtime_stats()
            process_stats = monitor.get_process_network_usage()
            
            up_kbps = stats["upload_speed_bps"] / 1024
            down_kbps = stats["download_speed_bps"] / 1024
            
            # Update metric components
            upload_metric.metric("Upload Speed", f"{up_kbps:.2f} KB/s")
            download_metric.metric("Download Speed", f"{down_kbps:.2f} KB/s")
            
            # Update chart data
            current_time = time.strftime("%H:%M:%S")
            new_data = pd.DataFrame(
                {"Upload (KB/s)": [up_kbps], "Download (KB/s)": [down_kbps]},
                index=[current_time]
            )
            
            df = pd.concat([df, new_data])
            if len(df) > 60:
                df = df.iloc[-60:]
                
            chart_placeholder.line_chart(df)
            
            # Update Process Table
            if process_stats:
                formatted_stats = []
                for p in process_stats:
                    formatted_stats.append({
                        "PID": p["pid"],
                        "Process Name": p["name"],
                        "Upload (KB/s)": round(p["upload_speed_bps"] / 1024, 2),
                        "Download (KB/s)": round(p["download_speed_bps"] / 1024, 2),
                        "Total (KB/s)": round(p["total_speed_bps"] / 1024, 2)
                    })
                proc_df = pd.DataFrame(formatted_stats)
            else:
                proc_df = pd.DataFrame(columns=["PID", "Process Name", "Upload (KB/s)", "Download (KB/s)", "Total (KB/s)"])
                
            table_placeholder.dataframe(proc_df, use_container_width=True, hide_index=True)
            
            # Wait for 1 second before the next refresh
            time.sleep(1)
            
    except Exception as e:
         st.error(f"Monitoring stopped or an error occurred: {e}")

if __name__ == "__main__":
    run_ui()
