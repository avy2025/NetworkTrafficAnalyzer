import queue
import time
from collections import defaultdict

class TrafficAnalyzer:
    def __init__(self, logger=None):
        """
        Initializes the traffic analyzer with advanced anomaly detection heuristics.
        
        Args:
            logger (CSVLogger): Persistence component for logging network events.
        """
        self.packet_queue = queue.Queue()
        self.logger = logger
        
        self.ip_counts = defaultdict(int)        
        self.protocol_counts = defaultdict(int)  
        self.traffic_history = []  
        self.anomalies = []        
        
        self.rolling_window_sec = 10 
        self.anomaly_multiplier = 4.0 
        self.flood_threshold = 1000 # Packets per window
        self.exfil_threshold = 1024 * 1024 # 1MB per window per IP

    def process_packet(self, packet_data):
        self.packet_queue.put(packet_data)

    def extract_insights(self):
        """
        Processes the packet queue and runs detection heuristics.
        Returns a dictionary of current traffic insights and active anomalies.
        """
        current_time = time.time()
        interval_bytes = 0
        window_ip_bytes = defaultdict(int)
        window_ip_packets = defaultdict(int)
        
        while not self.packet_queue.empty():
            try:
                pkt = self.packet_queue.get_nowait()
                size = pkt.get("size", 0)
                src = pkt.get("src_ip", "Unknown")
                dst = pkt.get("dst_ip", "Unknown")
                
                self.ip_counts[src] += size
                self.ip_counts[dst] += size
                self.protocol_counts[pkt.get("protocol", "Other")] += size
                
                window_ip_bytes[src] += size
                window_ip_packets[src] += 1
                
                interval_bytes += size
            except queue.Empty:
                break
                
        # Clean up old history
        self.traffic_history = [x for x in self.traffic_history if current_time - x["time"] <= self.rolling_window_sec]
        
        # 1. Bandwidth Spike Detection
        if len(self.traffic_history) >= 3 and interval_bytes > 50000:
            avg_traffic = sum(x["bytes"] for x in self.traffic_history) / len(self.traffic_history)
            if avg_traffic > 0 and interval_bytes > (avg_traffic * self.anomaly_multiplier):
                self._add_anomaly(
                    "Bandwidth Spike",
                    f"Traffic surge: {interval_bytes/1024:.1f} KB/s (Baseline: {avg_traffic/1024:.1f} KB/s)",
                    "High"
                )

        # 2. DDoS / Flood Detection
        for ip, count in window_ip_packets.items():
            if count > self.flood_threshold:
                self._add_anomaly(
                    "Connection Flood",
                    f"IP {ip} is sending packets at an extreme rate ({count} pkts/window)",
                    "Critical"
                )

        # 3. Data Exfiltration Alert
        for ip, bytes_seen in window_ip_bytes.items():
            if bytes_seen > self.exfil_threshold:
                self._add_anomaly(
                    "Data Exfiltration",
                    f"Suspicious outbound volume from {ip}: {bytes_seen/(1024*1024):.1f} MB",
                    "High"
                )
                    
        if interval_bytes > 0 or len(self.traffic_history) == 0:
             self.traffic_history.append({"time": current_time, "bytes": interval_bytes})

        # Prepare outputs for UI
        sorted_ips = sorted(self.ip_counts.items(), key=lambda item: item[1], reverse=True)[:5]
        top_ips = [{"ip": k, "bytes": v} for k, v in sorted_ips]
        
        sorted_protos = sorted(self.protocol_counts.items(), key=lambda item: item[1], reverse=True)
        top_protos = [{"protocol": k, "bytes": v} for k, v in sorted_protos]
        
        return {
            "top_ips": top_ips,
            "top_protocols": top_protos,
            "anomalies": self.anomalies
        }

    def _add_anomaly(self, atype, desc, severity):
        """Internal helper to structure and persist anomalies."""
        timestamp = time.strftime('%H:%M:%S')
        anomaly_obj = {
            "timestamp": timestamp,
            "type": atype,
            "description": desc,
            "severity": severity
        }
        
        # Avoid duplicate anomalies of same type/desc in the same window (simple throttle)
        if self.anomalies and self.anomalies[0]["description"] == desc:
            return

        self.anomalies.insert(0, anomaly_obj)
        if len(self.anomalies) > 15:
            self.anomalies = self.anomalies[:15]

        if self.logger:
            self.logger.log_anomaly(atype, desc, severity)
