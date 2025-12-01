import logging
from scapy.all import wrpcap, IP, UDP, TCP, Ether
import random
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_pcap(filename="test_traffic.pcap", packet_count=20000):
    """
    Generates a pcap file with random packets.
    """
    logging.info(f"Generating {packet_count} packets for {filename}...")
    packets = []
    
    for i in range(packet_count):
        # Randomize src and dst within 127.0.0.x
        src_ip = f"127.0.0.{random.randint(1, 254)}"
        #dst_ip = f"127.0.0.{random.randint(1, 254)}"
        dst_ip = "127.0.0.1"
        
        # Randomize ports
        sport = random.randint(1024, 65535)
        #dport = random.randint(1024, 65535)
        dport = 12345
        
        # Random payload
        payload_size = random.randint(16, 128) # Keep it small for easy debugging, but variable
        payload = os.urandom(payload_size)
        
        # Create packet (Ethernet/IP/UDP) - using UDP for simplicity, but TCP works too
        # We need Ethernet header for a valid pcap that looks like wire capture
        pkt = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / payload
        packets.append(pkt)
        
    wrpcap(filename, packets)
    logging.info(f"Successfully generated {filename} with {len(packets)} packets.")

if __name__ == "__main__":
    generate_pcap()
