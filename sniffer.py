from scapy.all import sniff, IP, TCP, UDP, DNS
import threading
import time

class PacketSniffer:
    def __init__(self, analyzer):
        """
        Initializes the sniffer.
        
        Args:
            analyzer (TrafficAnalyzer): The instance that will process extracted packets.
        """
        self.analyzer = analyzer
        self.stop_event = threading.Event()
        self.thread = None

    def start(self):
        """Starts the packet sniffing operation in an asynchronous background daemon thread."""
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()

    def stop(self):
        """Gracefully halts the sniffing thread."""
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)

    def _sniff_loop(self):
        """The core scapy sniffer operation. Blocks thread execution until requested to stop."""
        # Setting store=False acts as a pure stream buffer so RAM footprint remains low
        sniff(
            filter="tcp or udp",
            prn=self._process_packet,
            store=False,
            stop_filter=lambda x: self.stop_event.is_set()
        )

    def _process_packet(self, packet):
        """Callback to extract network telemetry on each tick directly from Scapy packets."""
        try:
            # We strictly enforce IP-based targeting
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_size = len(packet)
                timestamp = time.time()
                
                # Protocol layer classification (TCP/UDP/HTTP/DNS)
                protocol = "IP"
                if TCP in packet:
                    if packet[TCP].sport == 80 or packet[TCP].dport == 80:
                        protocol = "HTTP"
                    elif packet[TCP].sport == 443 or packet[TCP].dport == 443:
                        protocol = "HTTPS"
                    else:
                        protocol = "TCP"
                elif UDP in packet:
                    if DNS in packet or packet[UDP].sport == 53 or packet[UDP].dport == 53:
                        protocol = "DNS"
                    else:
                        protocol = "UDP"

                # Standardize object for the Analyzer thread
                packet_data = {
                    "timestamp": timestamp,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "size": packet_size
                }
                
                # Thread-safely ship the metadata dictionary
                self.analyzer.process_packet(packet_data)
                
        except Exception:
            # A strict catch rule drops malformed packets protecting the background thread from fatally crashing 
            pass
