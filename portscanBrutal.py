import socket
import time

target_ip = "127.0.0.1"  # scan own machine
start_port = 1
end_port = 100           # end range
delay = 0.05             # 50ms delay between ports

print(f"Scanning {target_ip} from port {start_port} to {end_port}")

for port in range(start_port, end_port + 1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)  # Timeout quickly
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            print(f"Port {port}: OPEN")
        sock.close()
        time.sleep(delay)
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
