import queue
import time
from collections import defaultdict

class TrafficAnalyzer:
    def __init__(self):
        """Initializes the traffic analyzer with a thread-safe data ingestion queue."""
        self.packet_queue = queue.Queue()
        
        # State tracking dictionaries for identifying network dominators
        self.ip_counts = defaultdict(int)        
        self.protocol_counts = defaultdict(int)  
        
        # Anomaly Detection tracking
        self.traffic_history = []  
        self.anomalies = []        
        
        # Thresholds defining acceptable baseline traffic behavior
        self.rolling_window_sec = 10 
        self.anomaly_multiplier = 3.0 

    def process_packet(self, packet_data):
        """Ingests parsed packet data dynamically from Sniffer thread background loops."""
        self.packet_queue.put(packet_data)

    def extract_insights(self):
        """
        Consumes all queued packets instantly off the processing pipeline. 
        Calculates heuristics continuously and maps dictionaries into clean JSON outputs for the UI.
        
        Returns:
            dict: Insights mapped cleanly for Streamlit component ingestion
        """
        current_time = time.time()
        interval_bytes = 0
        
        # Fast Pipeline Drain loop
        while not self.packet_queue.empty():
            try:
                pkt = self.packet_queue.get_nowait()
                size = pkt.get("size", 0)
                
                # Increment metrics
                self.ip_counts[pkt["src_ip"]] += size
                self.ip_counts[pkt["dst_ip"]] += size
                self.protocol_counts[pkt["protocol"]] += size
                
                # Keep rolling count 
                interval_bytes += size
                
            except queue.Empty:
                break
                
        # --- Heuristic Data Point Cleaning ---
        # Discard trailing values beyond the 10-second bound
        self.traffic_history = [x for x in self.traffic_history if current_time - x["time"] <= self.rolling_window_sec]
        
        if len(self.traffic_history) >= 3 and interval_bytes > 0:
            # Determine baseline standard via simple window average
            avg_traffic = sum(x["bytes"] for x in self.traffic_history) / len(self.traffic_history)
            
            # Simple Spiking logic - Flag occurrences > 3x average with 50KB total tolerance offset
            if avg_traffic > 0 and interval_bytes > (avg_traffic * self.anomaly_multiplier) and interval_bytes > 50000:
                anomaly_msg = f"[{time.strftime('%H:%M:%S')}] Bandwidth Spike! Processing {interval_bytes/1024:.2f} KB/s against strict baseline of {avg_traffic/1024:.2f} KB/s!"
                self.anomalies.insert(0, anomaly_msg) 
                
                # Purge older reports to cap memory limits
                if len(self.anomalies) > 10:
                    self.anomalies = self.anomalies[:10]
                    
        # Retain history
        if interval_bytes > 0 or len(self.traffic_history) == 0:
             self.traffic_history.append({"time": current_time, "bytes": interval_bytes})

        # --- Dashboard Object Structuring ---
        sorted_ips = sorted(self.ip_counts.items(), key=lambda item: item[1], reverse=True)[:5]
        top_ips = [{"ip": k, "bytes": v} for k, v in sorted_ips]
        
        sorted_protos = sorted(self.protocol_counts.items(), key=lambda item: item[1], reverse=True)
        top_protos = [{"protocol": k, "bytes": v} for k, v in sorted_protos]
        
        return {
            "top_ips": top_ips,
            "top_protocols": top_protos,
            "anomalies": self.anomalies
        }
