import psutil
import time

class NetworkMonitor:
    """
    Monitors system-wide and process-specific network usage using psutil.
    """
    def __init__(self):
        """
        Initializes the monitor with baseline network statistics.
        """
        self.prev_stats = psutil.net_io_counters()
        self.prev_time = time.time()

        # For process-wise tracking mapping PID to io_counters
        self.prev_process_io = {}
        self.prev_process_time = time.time()

    def get_realtime_stats(self):
        """
        Calculates current system-wide upload and download speeds.
        
        Returns:
            dict: Current speeds (bps) and total volumes (bytes).
        """
        curr_stats = psutil.net_io_counters()
        curr_time = time.time()
        
        time_elapsed = curr_time - self.prev_time
        if time_elapsed <= 0:
            time_elapsed = 1e-9
            
        upload_speed_bps = (curr_stats.bytes_sent - self.prev_stats.bytes_sent) / time_elapsed
        download_speed_bps = (curr_stats.bytes_recv - self.prev_stats.bytes_recv) / time_elapsed
        
        self.prev_stats = curr_stats
        self.prev_time = curr_time
        
        return {
            "upload_speed_bps": upload_speed_bps,
            "download_speed_bps": download_speed_bps,
            "total_bytes_sent": curr_stats.bytes_sent,
            "total_bytes_recv": curr_stats.bytes_recv
        }

    def get_process_network_usage(self):
        """
        Heuristically maps network I/O to active processes.
        
        Note:
            On Windows, process-level I/O counters include both disk and network activity.
            This method filters for processes with active internet connections to improve accuracy.
        
        Returns:
            list: Top 10 processes ranked by total network intensity.
        """
        current_time = time.time()
        time_elapsed = current_time - self.prev_process_time
        if time_elapsed <= 0:
            time_elapsed = 1e-9

        # Identify PIDs with active network connections
        active_pids = set()
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.pid is not None:
                    active_pids.add(conn.pid)
        except psutil.AccessDenied:
            # Silently fail if connection inspection is restricted
            pass

        process_stats = []
        new_process_io = {}

        # Aggregate IO counters for active PIDs
        for pid in active_pids:
            try:
                proc = psutil.Process(pid)
                io = proc.io_counters()
                
                new_process_io[pid] = io
                
                if pid in self.prev_process_io:
                    prev_io = self.prev_process_io[pid]
                    read_bps = (io.read_bytes - prev_io.read_bytes) / time_elapsed
                    write_bps = (io.write_bytes - prev_io.write_bytes) / time_elapsed
                    
                    if read_bps > 0 or write_bps > 0:
                        process_stats.append({
                            "pid": pid,
                            "name": proc.name(),
                            "upload_speed_bps": write_bps,
                            "download_speed_bps": read_bps,
                            "total_speed_bps": read_bps + write_bps
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
        self.prev_process_io = new_process_io
        self.prev_process_time = current_time
        
        process_stats.sort(key=lambda x: x["total_speed_bps"], reverse=True)
        return process_stats[:10]
