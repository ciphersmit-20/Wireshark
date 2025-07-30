import pyshark
from collections import defaultdict

cap = pyshark.FileCapture('samples/sample_capture.pcap', keep_packets=False)
protocol_counts = defaultdict(int)
total_packets = 0

print(" Analyzing packets...\n")

try:
    for pkt in cap:
        total_packets += 1
        try:
            proto = pkt.highest_layer
            protocol_counts[proto] += 1
        except:
            protocol_counts["Unknown"] += 1
except Exception as e:
    print(" Error:", e)

# Output results
print(" Packet Type Summary")
print("----------------------")
print(f"Total Packets: {total_packets}")
for proto, count in sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"{proto}: {count}")
