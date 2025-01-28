from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import threading

class NetworkAnalyzer:
    def __init__(self):
        self.packet_stats = {
            "total_packets": 0,
            "protocols": defaultdict(int),
            "ips": defaultdict(int),
            "ports": defaultdict(int),
        }
        self.suspicious_ips = defaultdict(int)
        self.alert_threshold = 100  # Example threshold for suspicious activity

    def process_packet(self, packet):
        """Process a single packet and update statistics."""
        self.packet_stats["total_packets"] += 1

        # Analyze protocol
        if IP in packet:
            ip_layer = packet[IP]
            self.packet_stats["protocols"][ip_layer.proto] += 1

            # Source and Destination IPs
            self.packet_stats["ips"][ip_layer.src] += 1
            self.packet_stats["ips"][ip_layer.dst] += 1

            # Suspicious Traffic Detection
            if self.packet_stats["ips"][ip_layer.src] > self.alert_threshold:
                self.suspicious_ips[ip_layer.src] += 1

        # Analyze ports (TCP/UDP)
        if TCP in packet or UDP in packet:
            transport_layer = packet[TCP] if TCP in packet else packet[UDP]
            self.packet_stats["ports"][transport_layer.sport] += 1
            self.packet_stats["ports"][transport_layer.dport] += 1

    def capture_packets(self, interface):
        """Start capturing packets on a specific interface."""
        print(f"Starting packet capture on interface: {interface}")
        sniff(iface=interface, prn=self.process_packet, store=False)

    def get_stats(self):
        """Return current statistics."""
        return self.packet_stats

    def get_alerts(self):
        """Return detected suspicious IPs."""
        return [ip for ip, count in self.suspicious_ips.items() if count > 0]

class TrafficAnalyzerUI:
    def __init__(self, analyzer):
        self.analyzer = analyzer

    def display_stats(self):
        """Print statistics in a human-readable format."""
        stats = self.analyzer.get_stats()
        print("\n--- Network Traffic Statistics ---")
        print(f"Total Packets: {stats['total_packets']}")
        print("Protocols:")
        for proto, count in stats["protocols"].items():
            print(f"  {proto}: {count}")
        print("Source/Destination IPs:")
        for ip, count in stats["ips"].items():
            print(f"  {ip}: {count}")
        print("Ports:")
        for port, count in stats["ports"].items():
            print(f"  {port}: {count}")

    def display_alerts(self):
        """Print alerts for suspicious traffic patterns."""
        alerts = self.analyzer.get_alerts()
        if alerts:
            print("\n--- Suspicious Traffic Alerts ---")
            for ip in alerts:
                print(f"Suspicious Activity Detected from IP: {ip}")
        else:
            print("\nNo suspicious activity detected.")

def main():
    interface = "Wi-Fi"  # Replace with your system's active network interface
  # Replace with your interface, e.g., "eth0" or "Wi-Fi"

    analyzer = NetworkAnalyzer()
    ui = TrafficAnalyzerUI(analyzer)

    # Start packet capturing in a separate thread
    capture_thread = threading.Thread(target=analyzer.capture_packets, args=(interface,))
    capture_thread.daemon = True
    capture_thread.start()

    try:
        while True:
            ui.display_stats()
            ui.display_alerts()
            input("\nPress Enter to refresh stats...\n")
    except KeyboardInterrupt:
        print("\nStopping packet capture. Goodbye!")

if __name__ == "__main__":
    main()
