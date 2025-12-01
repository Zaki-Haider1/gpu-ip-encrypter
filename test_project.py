import logging
from scapy.all import rdpcap, wrpcap, IP, UDP, Ether
import socket
import struct
from gpu_aes import AESGpu
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ENCRYPTER_IP = "127.0.0.100"
DECRYPTER_IP = "127.0.0.200"
KEY = b'thisisasecretkey' # 16 bytes

def ip_to_bytes(ip):
    return socket.inet_aton(ip)

def bytes_to_ip(b):
    return socket.inet_ntoa(b)

def run_test():
    # 1. Generate Traffic
    if not os.path.exists("test_traffic.pcap"):
        logging.info("Generating pcap...")
        import pcap_gen
        pcap_gen.generate_pcap()
    
    packets = rdpcap("test_traffic.pcap")
    logging.info(f"Loaded {len(packets)} packets.")
    
    aes = AESGpu(KEY)
    
    encrypted_packets = []
    
    logging.info("Encrypting packets...")
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            payload = bytes(pkt[IP].payload)
            
            # Serialize: SrcIP (4) + DstIP (4) + Payload
            data_to_encrypt = ip_to_bytes(src_ip) + ip_to_bytes(dst_ip) + payload
            
            encrypted_data = aes.encrypt(data_to_encrypt)
            
            # Create new packet
            # Src = Encrypter, Dst = Decrypter
            # We keep Ethernet header but update IP
            new_pkt = pkt.copy()
            new_pkt[IP].src = ENCRYPTER_IP
            new_pkt[IP].dst = DECRYPTER_IP
            # We need to remove the payload layer (UDP/TCP) and replace with raw bytes
            # because the encrypted data is not a valid UDP/TCP segment anymore usually
            # But scapy handles Raw
            new_pkt[IP].remove_payload()
            new_pkt[IP].add_payload(encrypted_data)
            
            encrypted_packets.append(new_pkt)
            
    wrpcap("encrypted.pcap", encrypted_packets)
    logging.info(f"Saved {len(encrypted_packets)} encrypted packets to encrypted.pcap")
    
    # 2. Decrypt
    decrypted_packets = []
    logging.info("Decrypting packets...")
    
    for pkt in encrypted_packets:
        if IP in pkt:
            encrypted_data = bytes(pkt[IP].payload)
            
            try:
                decrypted_data = aes.decrypt(encrypted_data)
                
                # Parse: SrcIP (4) + DstIP (4) + Payload
                original_src_bytes = decrypted_data[:4]
                original_dst_bytes = decrypted_data[4:8]
                original_payload = decrypted_data[8:]
                
                original_src = bytes_to_ip(original_src_bytes)
                original_dst = bytes_to_ip(original_dst_bytes)
                
                # Reconstruct packet
                # We want to match the original packet structure
                # The original packet had UDP/TCP. The payload we extracted is the raw bytes of that UDP/TCP segment?
                # Wait, in the encryption step: `payload = bytes(pkt[IP].payload)`
                # `pkt[IP].payload` includes the UDP header if it's UDP.
                # So `original_payload` is the UDP/TCP header + data.
                
                # We can reconstruct the IP layer
                rec_pkt = pkt.copy()
                rec_pkt[IP].src = original_src
                rec_pkt[IP].dst = original_dst
                rec_pkt[IP].remove_payload()
                
                # Scapy is smart enough to re-dissect if we add the payload
                # But to be safe, we just add it as Raw, and then let Scapy re-build if needed
                # Or just trust it's the same bytes.
                
                # However, for comparison, we should compare the bytes of the IP payload.
                rec_pkt[IP].add_payload(original_payload)
                
                decrypted_packets.append(rec_pkt)
                
            except Exception as e:
                logging.error(f"Decryption failed for a packet: {e}")

    # 3. Verify
    logging.info("Verifying...")
    success_count = 0
    for i in range(len(packets)):
        orig = packets[i]
        dec = decrypted_packets[i]
        
        # Compare IP src, dst, and payload
        if (orig[IP].src == dec[IP].src and 
            orig[IP].dst == dec[IP].dst and 
            bytes(orig[IP].payload) == bytes(dec[IP].payload)):
            success_count += 1
        else:
            logging.error(f"Mismatch at packet {i}")
            logging.error(f"Orig: {orig[IP].src} -> {orig[IP].dst} | Len: {len(bytes(orig[IP].payload))}")
            logging.error(f"Dec:  {dec[IP].src} -> {dec[IP].dst} | Len: {len(bytes(dec[IP].payload))}")

    if success_count == len(packets):
        logging.info("SUCCESS: All packets recovered correctly!")
    else:
        logging.error(f"FAILURE: Only {success_count}/{len(packets)} packets recovered.")

if __name__ == "__main__":
    run_test()
