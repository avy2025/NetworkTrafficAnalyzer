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

    # Initialize the monitor component
    monitor = NetworkMonitor()
    
    # Initialize dataframe for chart history
    df = pd.DataFrame(columns=["Upload (KB/s)", "Download (KB/s)"])
    
    try:
        while True:
            # Fetch real-time data from Phase 1 monitor
            stats = monitor.get_realtime_stats()
            
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
            
            # Retain only the last 60 seconds to maintain readability and performance
            if len(df) > 60:
                df = df.iloc[-60:]
                
            chart_placeholder.line_chart(df)
            
            # Wait for 1 second before the next refresh
            time.sleep(1)
            
    except Exception as e:
         st.error(f"Monitoring stopped or an error occurred: {e}")

if __name__ == "__main__":
    run_ui()
