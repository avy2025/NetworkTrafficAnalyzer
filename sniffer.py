from scapy.all import sniff, IP, TCP, UDP, DNS
import threading
import time

class PacketSniffer:
    """
    Asynchronous network packet sniffer utilizing Scapy for real-time traffic interception.
    Captured metadata is normalized and dispatched to a TrafficAnalyzer instance.
    """
    def __init__(self, analyzer):
        """
        Initializes the sniffer with a target analyzer.
        
        Args:
            analyzer (TrafficAnalyzer): The instance responsible for processing packet telemetry.
        """
        self.analyzer = analyzer
        self.stop_event = threading.Event()
        self.thread = None

    def start(self):
        """
        Heads the sniffing operation in a dedicated background daemon thread.
        Non-blocking call that allows the main application to continue execution.
        """
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()

    def stop(self):
        """
        Signals the sniffing thread to terminate and waits for it to join.
        """
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)

    def _sniff_loop(self):
        """
        Internal loop executing the Scapy sniff function.
        Configured with store=False to maintain a minimal memory footprint.
        """
        sniff(
            filter="tcp or udp",
            prn=self._process_packet,
            store=False,
            stop_filter=lambda x: self.stop_event.is_set()
        )

    def _process_packet(self, packet):
        """
        Scapy callback for processing individual packets.
        Extracts source/destination IPs, protocol type, and payload size.
        """
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_size = len(packet)
                timestamp = time.time()
                
                # Protocol classification logic
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

                # Normalize metadata
                packet_data = {
                    "timestamp": timestamp,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "size": packet_size
                }
                
                self.analyzer.process_packet(packet_data)
                
        except Exception:
            # Swallow exceptions to prevent background thread crash from malformed packets
            pass
