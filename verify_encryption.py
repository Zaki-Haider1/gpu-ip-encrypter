from scapy.all import rdpcap, IP

orig = rdpcap("test_traffic.pcap")
enc = rdpcap("encrypted.pcap")

print(f"Original packets: {len(orig)}")
print(f"Encrypted packets: {len(enc)}")

diff_count = 0
for o, e in zip(orig, enc):
    if IP in o and IP in e:
        if bytes(o[IP].payload) != bytes(e[IP].payload):
            diff_count += 1

print(f"Packets with different payload: {diff_count}")
if diff_count == len(orig):
    print("VERIFICATION SUCCESS: All payloads are different.")
else:
    print("VERIFICATION FAILURE: Some payloads are identical.")
