from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, get_if_list
from collections import Counter


print()
print("NETWORK TRAFFIC ANALYZER")
print()

# Show available interfaces
interfaces = get_if_list()
print("Available interfaces:")
for i, iface in enumerate(interfaces):
    print(f"  {i + 1}. {iface}")

iface_choice = input(f"Pick interface (1-{len(interfaces)}) or Enter for all: ").strip()
if iface_choice:
    iface = interfaces[int(iface_choice) - 1]
    print(f"Sniffing on: {iface}")
else:
    iface = None
    print("Sniffing on all interfaces")

count = int(input("How many packets to capture: "))
filter_input = input("Enter BPF filter (or press Enter for none): ").strip()

print(f"Capturing {count} packets...")

if filter_input:
    packets = sniff(count=count, filter=filter_input, iface=iface)
else:
    packets = sniff(count=count, iface=iface)

print(f"Captured {len(packets)} packets")


tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0

for packet in packets:
    if packet.haslayer(TCP):
        tcp_count += 1
    elif packet.haslayer(UDP):
        udp_count += 1
    elif packet.haslayer(ICMP):
        icmp_count += 1
    else:
        other_count += 1

print(f"\n--- Protocol Breakdown ---")
print(f"  TCP:   {tcp_count}")
print(f"  UDP:   {udp_count}")
print(f"  ICMP:  {icmp_count}")
print(f"  Other: {other_count}")


src_ips = Counter()
dst_ips = Counter()

for packet in packets:
    if packet.haslayer(IP):
        src_ips[packet[IP].src] += 1
        dst_ips[packet[IP].dst] += 1

print(f"\n--- Top Source IPs ---")
for ip, pcount in src_ips.most_common(5):
    print(f"  {ip}: {pcount} packets")

print(f"\n--- Top Destination IPs ---")
for ip, pcount in dst_ips.most_common(5):
    print(f"  {ip}: {pcount} packets")


ports = Counter()

for packet in packets:
    if packet.haslayer(TCP):
        ports[packet[TCP].dport] += 1
    elif packet.haslayer(UDP):
        ports[packet[UDP].dport] += 1

common_ports = {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP", 3389: "RDP"}

print(f"\n--- Top Destination Ports ---")
for port, pcount in ports.most_common(5):
    service = common_ports.get(port, "Unknown")
    print(f"  Port {port} [{service}]: {pcount} packets")


total_bytes = 0

for packet in packets:
    total_bytes += len(packet)

print(f"\n--- Bandwidth ---")
print(f"  Total data captured: {total_bytes} bytes ({total_bytes / 1024:.1f} KB)")
print(f"  Average packet size: {total_bytes / len(packets):.0f} bytes")


dns_queries = []

for packet in packets:
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode()
        dns_queries.append(query)

if dns_queries:
    print(f"\n--- DNS Queries (domains being resolved) ---")
    for domain in set(dns_queries):
        print(f"  {domain}")
else:
    print(f"\n--- DNS Queries ---")
    print(f"  No DNS queries captured")


save = input("\nSave capture to file? (y/n): ").strip().lower()
if save == 'y':
    filename = input("Enter filename (e.g. capture.pcap): ").strip()
    wrpcap(filename, packets)
    print(f"Saved {len(packets)} packets to {filename}")
