import time
from monitor import NetworkMonitor

def format_speed(bps):
    """Helper formatting function to convert bytes/s to readable format."""
    if bps >= 1024 * 1024:
        return f"{bps / (1024 * 1024):.2f} MB/s"
    elif bps >= 1024:
        return f"{bps / 1024:.2f} KB/s"
    return f"{bps:.2f} B/s"

def main():
    print("Starting Network Monitor Test... (Press Ctrl+C to stop)")
    monitor = NetworkMonitor()
    
    try:
        while True:
            # Wait a second before polling again
            time.sleep(1)
            
            stats = monitor.get_realtime_stats()
            
            up_speed = format_speed(stats["upload_speed_bps"])
            down_speed = format_speed(stats["download_speed_bps"])
            
            # Print formatted data
            print(f"Up: {up_speed: <12} | Down: {down_speed: <12} | "
                  f"Total Sent: {stats['total_bytes_sent'] / (1024*1024):.2f} MB | "
                  f"Total Recv: {stats['total_bytes_recv'] / (1024*1024):.2f} MB")
            
    except KeyboardInterrupt:
        print("\nStopping Network Monitor.")

if __name__ == "__main__":
    main()
