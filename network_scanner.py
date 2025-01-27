import argparse
from scapy.all import sr1, IP, TCP

def scan_ports(ip, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP) and response[TCP].flags == "SA":
            open_ports.append(port)
    return open_ports

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")
    parser.add_argument("ip", help="IP address to scan")
    parser.add_argument("-s", "--start-port", type=int, default=1, help="Starting port (default: 1)")
    parser.add_argument("-e", "--end-port", type=int, default=1024, help="Ending port (default: 1024)")
    args = parser.parse_args()

    open_ports = scan_ports(args.ip, args.start_port, args.end_port)
    print("Open ports:", open_ports)