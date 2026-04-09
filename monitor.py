import psutil
import time

class NetworkMonitor:
    def __init__(self):
        """Initializes the monitor with current network stats and time."""
        self.prev_stats = psutil.net_io_counters()
        self.prev_time = time.time()

        # For process-wise tracking mapping PID to io_counters
        self.prev_process_io = {}
        self.prev_process_time = time.time()

    def get_realtime_stats(self):
        """
        Calculates real-time upload and download speeds.
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

    def get_process_network_usage(self):
        """
        Approximates per-process network usage using psutil io_counters().
        
        NOTE: On Windows, psutil.Process(pid).io_counters() returns combined Disk and Network I/O.
        This function approximates network usage by only considering processes with active
        network connections. It is designed to be replaced by accurate packet sniffing in Phase 4.
        
        Returns:
            list: A list of dictionaries containing top 10 processes by I/O activity.
        """
        current_time = time.time()
        time_elapsed = current_time - self.prev_process_time
        if time_elapsed == 0:
            time_elapsed = 1e-9

        # Identify PIDs with active network connections
        active_pids = set()
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.pid is not None:
                    active_pids.add(conn.pid)
        except psutil.AccessDenied:
            # Some connections might require admin privileges to inspect
            pass

        process_stats = []
        new_process_io = {}

        # Get IO counters for active PIDs
        for pid in active_pids:
            try:
                proc = psutil.Process(pid)
                io = proc.io_counters()
                
                new_process_io[pid] = io
                
                # Compare against previous state if it exists
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
                # Handle process termination gracefully
                continue
                
        # Update state for next poll
        self.prev_process_io = new_process_io
        self.prev_process_time = current_time
        
        # Sort by total activity and limit to Top 10 processes for performance
        process_stats.sort(key=lambda x: x["total_speed_bps"], reverse=True)
        return process_stats[:10]
