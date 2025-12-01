import socket
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HOST = "127.0.0.1"
PORT = 12345

def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((HOST, PORT))
        logging.info(f"Destination listening on {HOST}:{PORT}")
        
        while True:
            data, addr = sock.recvfrom(65535)
            logging.info(f"Received packet from {addr}: {len(data)} bytes")
            print(data)
            # We expect raw payload here? Or the full packet?
            # The Decrypter sends "IP(src=OriginalSrc, dst=OriginalDst) / UDP / Payload"
            # If Decrypter uses raw socket or scapy send, it sends a full IP packet.
            # If Destination is a standard UDP socket, it receives the PAYLOAD of the UDP packet destined to it.
            # If Decrypter sends a UDP packet to 127.0.0.1:12345, the OS stack handles IP/UDP headers
            # and gives the payload to this socket.
            
            
            logging.info(f"Payload: {data[:20]}...")

    except Exception as e:
        logging.error(f"Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    start_server()
