import socket
import logging
from gpu_aes import AESGpu
from scapy.all import IP
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HOST = "127.0.0.100" # Encrypter IP
PORT = 9999
DECRYPTER_IP = "127.0.0.200"
DECRYPTER_PORT = 9999
KEY = b'thisisasecretkey'

def ip_to_bytes(ip):
    return socket.inet_aton(ip)

def start_encrypter():
    try:
        aes = AESGpu(KEY)
        logging.info("GPU AES initialized.")
    except Exception as e:
        logging.error(f"Failed to init GPU AES: {e}")
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((HOST, PORT))
        logging.info(f"Encrypter listening on {HOST}:{PORT}")
        
        while True:
            # We expect to receive the raw IP packet as payload from Injector
            # Or does Injector send a UDP packet with the IP packet as payload?
            # Yes, Injector "tunnels" the IP packet.
            data, addr = sock.recvfrom(65535)
            logging.info(f"Received {len(data)} bytes from {addr}")
            
            try:
                # Parse the inner IP packet to get Src/Dst/Payload
                # We can use Scapy to parse the bytes
                pkt = IP(data)
                
                src_ip = pkt.src
                dst_ip = pkt.dst
                # Payload of IP (includes UDP/TCP header)
                payload = bytes(pkt.payload)
                
                logging.info(f"Encrypting packet: {src_ip} -> {dst_ip}")
                
                # Serialize: SrcIP (4) + DstIP (4) + Payload
                data_to_encrypt = ip_to_bytes(src_ip) + ip_to_bytes(dst_ip) + payload
                
                # Encrypt
                encrypted_data = aes.encrypt(data_to_encrypt)
                
                # Send to Decrypter
                sock.sendto(encrypted_data, (DECRYPTER_IP, DECRYPTER_PORT))
                logging.info(f"Sent encrypted data to {DECRYPTER_IP}:{DECRYPTER_PORT}")

            except Exception as e:
                logging.error(f"Processing failed: {e}")

    except Exception as e:
        logging.error(f"Socket error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    start_encrypter()
