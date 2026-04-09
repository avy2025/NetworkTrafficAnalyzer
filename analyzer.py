import queue
import time
from collections import defaultdict

class TrafficAnalyzer:
    def __init__(self, logger=None):
        """
        Initializes the traffic analyzer featuring optional logger coupling for direct data shipping!
        
        Args:
            logger (CSVLogger): Active File I/O logger component handling anomaly event streams
        """
        self.packet_queue = queue.Queue()
        self.logger = logger
        
        self.ip_counts = defaultdict(int)        
        self.protocol_counts = defaultdict(int)  
        self.traffic_history = []  
        self.anomalies = []        
        
        self.rolling_window_sec = 10 
        self.anomaly_multiplier = 3.0 

    def process_packet(self, packet_data):
        self.packet_queue.put(packet_data)

    def extract_insights(self):
        """Consumes queue actively returning GUI layouts while concurrently processing internal ML heuristics."""
        current_time = time.time()
        interval_bytes = 0
        
        while not self.packet_queue.empty():
            try:
                pkt = self.packet_queue.get_nowait()
                size = pkt.get("size", 0)
                
                self.ip_counts[pkt["src_ip"]] += size
                self.ip_counts[pkt["dst_ip"]] += size
                self.protocol_counts[pkt["protocol"]] += size
                
                interval_bytes += size
            except queue.Empty:
                break
                
        self.traffic_history = [x for x in self.traffic_history if current_time - x["time"] <= self.rolling_window_sec]
        
        if len(self.traffic_history) >= 3 and interval_bytes > 0:
            avg_traffic = sum(x["bytes"] for x in self.traffic_history) / len(self.traffic_history)
            
            # Complex Spiking logic (Phase 5 Analytics)
            if avg_traffic > 0 and interval_bytes > (avg_traffic * self.anomaly_multiplier) and interval_bytes > 50000:
                anomaly_type = "Bandwidth Spike"
                desc = f"Processing {interval_bytes/1024:.2f} KB/s against strict baseline of {avg_traffic/1024:.2f} KB/s!"
                severity = "High"
                
                # Formats string strictly exclusively for UI Rendering
                ui_msg = f"[{time.strftime('%H:%M:%S')}] {anomaly_type}! {desc}"
                self.anomalies.insert(0, ui_msg) 
                
                # Route structurally directly into CSV storage skipping intermediate variables
                if self.logger:
                    self.logger.log_anomaly(anomaly_type, desc, severity)
                
                if len(self.anomalies) > 10:
                    self.anomalies = self.anomalies[:10]
                    
        if interval_bytes > 0 or len(self.traffic_history) == 0:
             self.traffic_history.append({"time": current_time, "bytes": interval_bytes})

        # Process clean object payload structures out to GUI logic scopes
        sorted_ips = sorted(self.ip_counts.items(), key=lambda item: item[1], reverse=True)[:5]
        top_ips = [{"ip": k, "bytes": v} for k, v in sorted_ips]
        
        sorted_protos = sorted(self.protocol_counts.items(), key=lambda item: item[1], reverse=True)
        top_protos = [{"protocol": k, "bytes": v} for k, v in sorted_protos]
        
        return {
            "top_ips": top_ips,
            "top_protocols": top_protos,
            "anomalies": self.anomalies
        }
