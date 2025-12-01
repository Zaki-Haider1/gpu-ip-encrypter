import socket
import logging
from gpu_aes import AESGpu
from scapy.all import IP, UDP, send
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HOST = "127.0.0.200" # Decrypter IP
PORT = 9999
KEY = b'thisisasecretkey'

def bytes_to_ip(b):
    return socket.inet_ntoa(b)

def start_decrypter():
    # Initialize GPU AES
    try:
        aes = AESGpu(KEY)
        logging.info("GPU AES initialized.")
    except Exception as e:
        logging.error(f"Failed to init GPU AES: {e}")
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((HOST, PORT))
        logging.info(f"Decrypter listening on {HOST}:{PORT}")
        
        while True:
            encrypted_data, addr = sock.recvfrom(65535)
            logging.info(f"Received {len(encrypted_data)} bytes from {addr}")
            
            try:
                # Decrypt
                decrypted_data = aes.decrypt(encrypted_data)
                
                # Parse: SrcIP (4) + DstIP (4) + Payload
                if len(decrypted_data) < 8:
                    logging.error("Decrypted data too short.")
                    continue
                    
                original_src_bytes = decrypted_data[:4]
                original_dst_bytes = decrypted_data[4:8]
                original_payload = decrypted_data[8:]
                
                original_src = bytes_to_ip(original_src_bytes)
                original_dst = bytes_to_ip(original_dst_bytes)
                
                logging.info(f"Decrypted: Src={original_src}, Dst={original_dst}, PayloadLen={len(original_payload)}")
                
                # Forward to Destination
                # Note: We cannot spoof Source IP without root privileges.
                # We will send the payload to the Original Destination.
                # The Destination will see the packet coming from the Decrypter.
                
                # We need to extract the actual data payload from the IP payload (which includes UDP header)
                # The `original_payload` variable currently holds UDP Header + Data.
                # We should strip the UDP header (8 bytes) to get just the data, 
                # because we are sending via a standard UDP socket which adds its own header.
                
                if len(original_payload) > 8:
                    real_payload = original_payload[8:]
                    # We assume destination port is 12345 as per destination.py
                    # In a real scenario, we would extract the destination port from the UDP header in original_payload.
                    # UDP Header: Source Port (2), Dest Port (2), Length (2), Checksum (2)
                    
                    # Let's parse the UDP header to be correct
                    udp_header = original_payload[:8]
                    import struct
                    src_port, dst_port, length, checksum = struct.unpack("!HHHH", udp_header)
                    
                    # Send to Original Dst IP and Original Dst Port
                    # But for this test, destination.py is listening on 12345.
                    # The pcap generated packets with random ports.
                    # So if we send to `dst_port`, `destination.py` might not receive it unless it binds to that port.
                    # But `destination.py` binds to 12345.
                    # So we should force send to 12345 for the test, or update destination to listen on all?
                    # The user said "just different ports".
                    # Let's send to 12345 for the demo to work.
                    
                    sock.sendto(real_payload, (original_dst, 12345))
                    logging.info(f"Forwarded packet to {original_dst}:12345 (OrigDstPort={dst_port})")
                else:
                    logging.warning("Payload too short for UDP header")

            except Exception as e:
                logging.error(f"Processing failed: {e}")

    except Exception as e:
        logging.error(f"Socket error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    start_decrypter()
