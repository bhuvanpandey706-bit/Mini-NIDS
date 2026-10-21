import os
from scapy.all import IP, TCP, wrpcap, rdpcap
from collections import defaultdict
from datetime import datetime


def detect_threats(packets, port_threshold=5, syn_threshold=10):
    source_ports = defaultdict(set)
    syn_counts = defaultdict(int)

    for packet in packets:
        if IP in packet and TCP in packet:
            source_ip = packet[IP].src
            tcp_layer = packet[TCP]

            source_ports[source_ip].add(tcp_layer.dport)

            # Count TCP SYN packets that are not SYN-ACK
            if tcp_layer.flags & 0x02 and not tcp_layer.flags & 0x10:
                syn_counts[source_ip] += 1

    alerts = []

    for source_ip, ports in source_ports.items():
        if len(ports) >= port_threshold:
            alerts.append(
                f"Potential TCP port scan: source={source_ip}, "
                f"unique_ports={len(ports)}"
            )

    for source_ip, count in syn_counts.items():
        if count >= syn_threshold:
            alerts.append(
                f"High TCP SYN count: source={source_ip}, "
                f"syn_packets={count}"
            )

    return source_ports, syn_counts, alerts


pcap_file = input(
    "Enter PCAP file path (press Enter for test_traffic.pcap): "
).strip()

use_test_traffic = not pcap_file

if use_test_traffic:
    pcap_file = "test_traffic.pcap"

    

# Create synthetic test traffic only when no PCAP was provided
if use_test_traffic:
    test_packets = []

    # Normal traffic
    for port in [80, 443]:
        test_packets.append(
            IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(sport=12345, dport=port, flags="S")
        )

    # Port-scan-like traffic
    for port in [21, 22, 23, 25, 53, 80, 443, 8080]:
        test_packets.append(
            IP(src="192.168.1.50", dst="192.168.1.20")
            / TCP(sport=12346, dport=port, flags="S")
        )

    # Repeated SYN attempts to test the second rule
    for _ in range(12):
        test_packets.append(
            IP(src="192.168.1.60", dst="192.168.1.20")
            / TCP(sport=12347, dport=80, flags="S")
        )

    wrpcap(pcap_file, test_packets)


if not os.path.exists(pcap_file):
    print(f"Error: {pcap_file} not found.")
    raise SystemExit(1)

packets = rdpcap(pcap_file)
print(f"Successfully loaded PCAP file: {pcap_file}")


try:
    port_threshold = int(input("Enter port-scan threshold (default 5): ") or "5")
    syn_threshold = int(input("Enter TCP SYN threshold (default 10): ") or "10")

    if port_threshold < 1 or syn_threshold < 1:
        raise ValueError("Thresholds must be positive integers.")

except ValueError as error:
    print(f"Invalid threshold: {error}")
    raise SystemExit(1)



source_ports, syn_counts, alerts = detect_threats(
    packets,
    port_threshold=port_threshold,
    syn_threshold=syn_threshold
)


print("Mini NIDS - Multiple Detection Rules")
print("-" * 40)

for source_ip in sorted(set(source_ports) | set(syn_counts)):
    print(f"\nSource IP: {source_ip}")
    print(f"Unique TCP ports: {len(source_ports[source_ip])}")
    print(f"TCP SYN packets: {syn_counts[source_ip]}")

for alert in alerts:
    if alert.startswith("Potential TCP port scan"):
        severity = "HIGH"
    elif alert.startswith("High TCP SYN count"):
        severity = "MEDIUM"
    else:
        severity = "LOW"

    print(f"[{severity} ALERT]", alert)

    
with open("nids_alerts.log", "a", encoding="utf-8") as log_file:
    log_file.write("\n" + "=" * 50 + "\n")
    log_file.write(
        f"NIDS run started: "
        f"{datetime.now().astimezone().isoformat(timespec='seconds')}\n"
    )

    for alert in alerts:
        timestamp = datetime.now().astimezone().isoformat(
            timespec="seconds"
        )
        
        if alert.startswith("Potential TCP port scan"):
            rule = "PORT_SCAN"
            severity = "HIGH"
        elif alert.startswith("High TCP SYN count"):
            rule = "HIGH_SYN_COUNT"
            severity = "MEDIUM"
        else:
            rule = "OTHER"
            severity = "LOW"

        
        log_entry = (
            f"{timestamp} | severity={severity} | "
            f"rule={rule} | {alert}\n"
        )

        log_file.write(log_entry)

    log_file.write(f"Total packets analyzed: {len(packets)}\n")
    log_file.write(f"Unique source IPs analyzed: {len(source_ports)}\n")
    log_file.write(f"Total alerts generated: {len(alerts)}\n")
    log_file.write("Detection run completed.\n")

print("Alerts saved to nids_alerts.log")

print("\n" + "=" * 40)
print(f"PCAP file analyzed: {pcap_file}")
print("MINI NIDS - DETECTION SUMMARY")
print("=" * 40)
print(f"Total packets analyzed: {len(packets)}")
print(f"Unique source IPs analyzed: {len(source_ports)}")
print(f"Port-scan alerts: {sum('Potential TCP port scan' in a for a in alerts)}")
print(f"High-SYN alerts: {sum('High TCP SYN count' in a for a in alerts)}")
print(f"Total alerts generated: {len(alerts)}")
print("=" * 40)
print("Detection run completed.")