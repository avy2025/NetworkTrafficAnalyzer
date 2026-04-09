import psutil
import time

class NetworkMonitor:
    def __init__(self):
        """Initializes the monitor with current network stats and time."""
        self.prev_stats = psutil.net_io_counters()
        self.prev_time = time.time()

    def get_realtime_stats(self):
        """
        Calculates real-time upload and download speeds.
        
        Returns:
            dict: Structured data containing current speeds (bps) and total bytes sent/received.
        """
        curr_stats = psutil.net_io_counters()
        curr_time = time.time()
        
        # Avoid division by zero
        time_elapsed = curr_time - self.prev_time
        if time_elapsed == 0:
            time_elapsed = 1e-9
            
        # Calculate speeds in bytes per second
        upload_speed_bps = (curr_stats.bytes_sent - self.prev_stats.bytes_sent) / time_elapsed
        download_speed_bps = (curr_stats.bytes_recv - self.prev_stats.bytes_recv) / time_elapsed
        
        # Update previous stats for the next call
        self.prev_stats = curr_stats
        self.prev_time = curr_time
        
        return {
            "upload_speed_bps": upload_speed_bps,
            "download_speed_bps": download_speed_bps,
            "total_bytes_sent": curr_stats.bytes_sent,
            "total_bytes_recv": curr_stats.bytes_recv
        }
