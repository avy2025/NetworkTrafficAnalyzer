import os
import csv
import threading
import time
from datetime import datetime

class CSVLogger:
    def __init__(self, log_dir="logs", max_bytes=5 * 1024 * 1024, buffer_size=10):
        """
        Engine for maintaining persistent telemetry. Features isolated threading locks and automatic file log rotation.
        
        Args:
            log_dir (str): Relative root to save CSV files.
            max_bytes (int): Trigger limit size defining when to archive and overwrite (5MB Default).
            buffer_size (int): IO Memory threshold. Stores entries up till bounds restricting heavy storage interactions.
        """
        self.log_dir = log_dir
        self.max_bytes = max_bytes
        self.buffer_size = buffer_size
        
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            
        self.network_log_path = os.path.join(self.log_dir, "network_log.csv")
        self.anomaly_log_path = os.path.join(self.log_dir, "anomalies.csv")
        
        self.network_buffer = []
        self.anomaly_buffer = []
        
        self.net_lock = threading.Lock()
        self.ano_lock = threading.Lock()
        
        # Hydrate Headers internally resolving blank environments
        self._ensure_header(self.network_log_path, ["timestamp", "datetime", "upload_kbps", "download_kbps"])
        self._ensure_header(self.anomaly_log_path, ["timestamp", "datetime", "type", "description", "severity"])

    def _ensure_header(self, filepath, headers):
        """Privatized method resolving CSV configuration dependencies"""
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            with open(filepath, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(headers)

    def _rotate_if_needed(self, filepath, headers):
        """Triggers local file system archiving retaining older CSV telemetry while flushing buffers to 0MB."""
        if os.path.exists(filepath) and os.path.getsize(filepath) >= self.max_bytes:
            base, ext = os.path.splitext(filepath)
            rotation_name = f"{base}_{int(time.time())}{ext}"
            os.rename(filepath, rotation_name)
            self._ensure_header(filepath, headers)

    def log_network(self, upload_kbps, download_kbps):
        """Queues pure Bandwidth throughput securely in cross-platform memory."""
        now = time.time()
        dt_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        
        with self.net_lock:
            self.network_buffer.append([now, dt_str, upload_kbps, download_kbps])
            if len(self.network_buffer) >= self.buffer_size:
                self._flush_network()

    def log_anomaly(self, anomaly_type, description, severity="High"):
        """Triggers an instantaneous hard-disk flush guaranteeing critical Event payloads are persisted without buffer delays!"""
        now = time.time()
        dt_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        
        with self.ano_lock:
            self.anomaly_buffer.append([now, dt_str, anomaly_type, description, severity])
            self._flush_anomaly()

    def _flush_network(self):
        """Protected method dropping mapped Network variables mechanically into the root CSV."""
        if not self.network_buffer:
            return
            
        headers = ["timestamp", "datetime", "upload_kbps", "download_kbps"]
        self._rotate_if_needed(self.network_log_path, headers)
        
        with open(self.network_log_path, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(self.network_buffer)
        self.network_buffer.clear()

    def _flush_anomaly(self):
        """Protected method dropping mapped Incident variables mechanically into the root CSV."""
        if not self.anomaly_buffer:
            return
            
        headers = ["timestamp", "datetime", "type", "description", "severity"]
        self._rotate_if_needed(self.anomaly_log_path, headers)
        
        with open(self.anomaly_log_path, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(self.anomaly_buffer)
        self.anomaly_buffer.clear()
        
    def get_network_log_content(self):
        """Frontend integration interface converting file system targets into pure strings ready for st.download() APIs"""
        self._flush_network()
        if os.path.exists(self.network_log_path):
            with open(self.network_log_path, "r") as f:
                return f.read()
        return ""
        
    def get_anomaly_log_content(self):
        """Frontend integration interface dumping Incident payloads directly"""
        self._flush_anomaly()
        if os.path.exists(self.anomaly_log_path):
            with open(self.anomaly_log_path, "r") as f:
                return f.read()
        return ""
