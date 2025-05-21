import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, conf, get_if_list

# Use Layer 3 sniffing (no Npcap)
conf.L2socket = conf.L3socket

# Port scan detection parameters
connection_attempts = defaultdict(list)
THRESHOLD = 10            # Number of unique ports to trigger alert
TIME_WINDOW = 10          # Time window in seconds
ALERT_COOLDOWN = 30

WHITELISTED_PORTS = {
    8089, 8191, 49401, 49809, 49814, 49843, 50350,
    51103, 51654, 51655, 51661, 51664, 64093, 64094, 64095
}

last_alert_time = {}

# Show available interfaces
print("Available interfaces:")
interfaces = get_if_list()
for idx, iface in enumerate(interfaces):
    print(f"{idx}: {iface}")

iface_index = int(input("\nEnter the number of the interface to monitor: "))
monitor_iface = interfaces[iface_index]
print(f"\n[+] Monitoring on interface: {monitor_iface}\n")

def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        timestamp = time.time()

        # Record connection attempt
        connection_attempts[src_ip].append((dst_port, timestamp))

        # Filter recent attempts within TIME_WINDOW
        recent = [
            (port, ts) for port, ts in connection_attempts[src_ip]
            if timestamp - ts < TIME_WINDOW
        ]
        connection_attempts[src_ip] = recent

        filtered_ports = [port for port, ts in recent if port not in WHITELISTED_PORTS]
        unique_ports = set(filtered_ports)

        if len(unique_ports) > THRESHOLD:
            print(f"\n[!] Port scan detected from {src_ip}")
            print(f"    ➤ Ports scanned: {sorted(unique_ports)}")
            

print("IDS is running. Press Ctrl+C to stop.\n")
sniff(
    iface=monitor_iface,
    filter="ip and tcp",
    prn=detect_port_scan,
    store=0
)
