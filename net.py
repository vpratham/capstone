from scapy.all import *
import re

# Known malicious IPs or ports to flag
malicious_ips = ['192.168.1.5', '10.0.0.8', '192.168.29.255']
malicious_ports = [4444, 1337, 6667]  # Commonly used in malware or suspicious activities

# Known attack patterns in payloads (e.g., SQL injection)
malicious_patterns = [
    b"SELECT .* FROM .*",  # SQL Injection pattern
    b"UNION SELECT",       # SQL Injection pattern
    b"\x90" * 20           # NOP sled (indicative of buffer overflow attack)
]

def flag_packet(packet):
    # Check if the packet has IP layer
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        # Flag if the source or destination is in the known malicious IPs list
        if ip_src in malicious_ips or ip_dst in malicious_ips:
            return True
        # Check if the packet has TCP/UDP layer
        elif TCP in packet or UDP in packet:
            sport = packet.sport
            dport = packet.dport
            # Flag if source or destination port is in known malicious ports list
            if sport in malicious_ports or dport in malicious_ports:
                return True
        # Flag for payload analysis
        elif Raw in packet:
            payload = bytes(packet[Raw].load)
            for pattern in malicious_patterns:
                if re.search(pattern, payload):
                    return True
        else:
            return False

# Sniff packets and apply the flag_packet function
#sniff(prn=flag_packet, filter="ip", store=0)