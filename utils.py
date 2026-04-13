import os
import csv
import threading
import time
from datetime import datetime

class CSVLogger:
    """
    Handles persistent telemetry logging with thread-safe file operations and automatic log rotation.
    """
    def __init__(self, log_dir="logs", max_bytes=5 * 1024 * 1024, buffer_size=10):
        """
        Initializes the CSV logger.
        
        Args:
            log_dir (str): Directory where CSV logs will be stored.
            max_bytes (int): Maximum size of a log file before rotation (default 5MB).
            buffer_size (int): Number of entries to buffer before flushing to disk.
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
        
        self._ensure_header(self.network_log_path, ["timestamp", "datetime", "upload_kbps", "download_kbps"])
        self._ensure_header(self.anomaly_log_path, ["timestamp", "datetime", "type", "description", "severity"])

    def _ensure_header(self, filepath, headers):
        """Ensures the CSV file exists and contains the specified headers."""
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            with open(filepath, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(headers)

    def _rotate_if_needed(self, filepath, headers):
        """Rotates the log file if it exceeds the maximum byte size."""
        if os.path.exists(filepath) and os.path.getsize(filepath) >= self.max_bytes:
            base, ext = os.path.splitext(filepath)
            rotation_name = f"{base}_{int(time.time())}{ext}"
            os.rename(filepath, rotation_name)
            self._ensure_header(filepath, headers)

    def log_network(self, upload_kbps, download_kbps):
        """
        Logs network throughput metrics.
        
        Args:
            upload_kbps (float): Current upload speed in KB/s.
            download_kbps (float): Current download speed in KB/s.
        """
        now = time.time()
        dt_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        
        with self.net_lock:
            self.network_buffer.append([now, dt_str, upload_kbps, download_kbps])
            if len(self.network_buffer) >= self.buffer_size:
                self._flush_network()

    def log_anomaly(self, anomaly_type, description, severity="High"):
        """
        Logs a detected security anomaly.
        
        Args:
            anomaly_type (str): The category of the anomaly.
            description (str): Detailed description of the event.
            severity (str): The severity level (Low, Medium, High, Critical).
        """
        now = time.time()
        dt_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        
        with self.ano_lock:
            self.anomaly_buffer.append([now, dt_str, anomaly_type, description, severity])
            self._flush_anomaly()

    def _flush_network(self):
        """Flushes buffered network logs to the CSV file."""
        if not self.network_buffer:
            return
            
        headers = ["timestamp", "datetime", "upload_kbps", "download_kbps"]
        self._rotate_if_needed(self.network_log_path, headers)
        
        with open(self.network_log_path, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(self.network_buffer)
        self.network_buffer.clear()

    def _flush_anomaly(self):
        """Flushes buffered anomaly logs to the CSV file."""
        if not self.anomaly_buffer:
            return
            
        headers = ["timestamp", "datetime", "type", "description", "severity"]
        self._rotate_if_needed(self.anomaly_log_path, headers)
        
        with open(self.anomaly_log_path, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(self.anomaly_buffer)
        self.anomaly_buffer.clear()
        
    def get_network_log_content(self):
        """Returns the entire content of the network log as a string."""
        self._flush_network()
        if os.path.exists(self.network_log_path):
            with open(self.network_log_path, "r") as f:
                return f.read()
        return ""
        
    def get_anomaly_log_content(self):
        """Returns the entire content of the anomaly log as a string."""
        self._flush_anomaly()
        if os.path.exists(self.anomaly_log_path):
            with open(self.anomaly_log_path, "r") as f:
                return f.read()
        return ""
