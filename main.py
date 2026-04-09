import time
from monitor import NetworkMonitor
from analyzer import TrafficAnalyzer
from sniffer import PacketSniffer

def format_speed(bps):
    """Helper formatting function to convert bytes/s to readable format."""
    if bps >= 1024 * 1024:
        return f"{bps / (1024 * 1024):.2f} MB/s"
    elif bps >= 1024:
        return f"{bps / 1024:.2f} KB/s"
    return f"{bps:.2f} B/s"

def main():
    print("Starting Advanced Network Traffic Analyzer... (Press Ctrl+C to stop)")
    
    # Initialize Phase 1 & 3 Base Monitoring
    monitor = NetworkMonitor()
    
    # Initialize Phase 4 Packet Sniffing & Aggregation
    analyzer = TrafficAnalyzer()
    sniffer = PacketSniffer(analyzer)
    
    # Fork sniffer sequence asynchronously
    sniffer.start()
    print("Sniffer thread successfully started in background!\n")

    try:
        while True:
            # Main UI / Output loop blocks for polling intervals
            time.sleep(1)
            
            # Extract basic statistical data
            stats = monitor.get_realtime_stats()
            up_speed = format_speed(stats["upload_speed_bps"])
            down_speed = format_speed(stats["download_speed_bps"])
            
            # Fetch summarized chunk from TrafficAnalyzer queue
            packets = analyzer.get_packets(max_packets=50) 
            
            if packets:
                # Provide summarized terminal UI without breaking or flooding logs 
                latest = packets[-1] 
                packet_peek = f"| Sniffed {len(packets)}+ live streams (Last: {latest['protocol']} {latest['src_ip']} -> {latest['dst_ip']}, {latest['size']}B)"
            else:
                packet_peek = "| No packet anomalies detected."

            # Terminal render logic
            print(f"Up: {up_speed: <12} | Down: {down_speed: <12} {packet_peek}")
            
    except KeyboardInterrupt:
        print("\nStopping Network Analyzer processes gracefully...")
    finally:
        # Enforce clean thread termination preventing lingering memory leaks
        sniffer.stop()

if __name__ == "__main__":
    main()
