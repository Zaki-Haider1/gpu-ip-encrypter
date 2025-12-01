import logging
from scapy.all import rdpcap, IP
import socket
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ENCRYPTER_IP = "127.0.0.100"
ENCRYPTER_PORT = 9999
PCAP_FILE = "test_traffic.pcap"

def run_injector():
    logging.info(f"Loading {PCAP_FILE}...")
    packets = rdpcap(PCAP_FILE)
    logging.info(f"Loaded {len(packets)} packets.")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    for i, pkt in enumerate(packets):
        if IP in pkt:
            # We want to send the whole IP packet as data
            # Scapy's bytes(pkt[IP]) gives the IP header + payload
            print(pkt[IP])
            data = bytes(pkt[IP])
            
            sock.sendto(data, (ENCRYPTER_IP, ENCRYPTER_PORT))
            logging.info(f"Injected packet {i+1}/{len(packets)}")
            
            # Small delay to not overwhelm
            time.sleep(0.01)
            
    logging.info("Injection complete.")

if __name__ == "__main__":
    run_injector()
