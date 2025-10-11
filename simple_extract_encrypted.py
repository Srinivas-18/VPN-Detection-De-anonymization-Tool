#!/usr/bin/env python3
"""
VPN Encrypted Data Extractor - Dynamic VPN Detection
"""

from scapy.all import rdpcap, Raw, IP, TCP, UDP
from collections import Counter
import binascii
import os

def extract_xvpn_encrypted_data(pcap_file: str):
    """Extract encrypted data from VPN packets - GUI compatible version"""
    try:
        packets = rdpcap(pcap_file)
        
        # Detect potential VPN IPs by analyzing traffic patterns
        vpn_candidates = _detect_vpn_ips_from_traffic(packets)
        
        encrypted_packets = []
        
        for i, pkt in enumerate(packets):
            if pkt.haslayer(Raw) and pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                
                # Check if packet involves any detected VPN IPs
                if any(ip in [src_ip, dst_ip] for ip in vpn_candidates):
                    raw_data = pkt[Raw].load
                    
                    packet_info = {
                        'packet_id': i,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'protocol': 'TCP' if pkt.haslayer(TCP) else 'UDP' if pkt.haslayer(UDP) else 'Other',
                        'src_port': pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0),
                        'dst_port': pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0),
                        'data_length': len(raw_data),
                        'hex_data': binascii.hexlify(raw_data).decode()
                    }
                
                    encrypted_packets.append(packet_info)
        
        return encrypted_packets
        
    except Exception as e:
        print(f"Error extracting encrypted data: {str(e)}")
        return []

def _detect_vpn_ips_from_traffic(packets):
    """Detect potential VPN IPs by analyzing traffic patterns"""
    ip_stats = Counter()
    port_443_ips = set()  # HTTPS/VPN traffic
    high_volume_ips = set()
    
    for pkt in packets:
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            # Count packet frequency
            ip_stats[src_ip] += 1
            ip_stats[dst_ip] += 1
            
            # Check for VPN-like ports (443, 1194, etc.)
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                sport = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport
                dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
                
                if sport == 443 or dport == 443:
                    port_443_ips.add(src_ip)
                    port_443_ips.add(dst_ip)
    
    # Find IPs with high traffic volume (potential VPN servers)
    total_packets = len(packets)
    for ip, count in ip_stats.items():
        if count > total_packets * 0.1:  # More than 10% of traffic
            high_volume_ips.add(ip)
    
    # Combine indicators to find VPN candidates
    vpn_candidates = port_443_ips.intersection(high_volume_ips)
    
    # If no clear candidates, return top traffic IPs
    if not vpn_candidates:
        vpn_candidates = [ip for ip, _ in ip_stats.most_common(3)]
    
    return list(vpn_candidates)

def extract_encrypted_data(pcap_file=None):
    """Extract encrypted data from VPN packets - standalone function"""
    if not pcap_file:
        print('⚠️  Please provide a PCAP file path')
        return 0
    
    print('🔒 EXTRACTING VPN ENCRYPTED DATA')
    print('=' * 50)
    
    try:
        encrypted_packets = extract_xvpn_encrypted_data(pcap_file)
        
        if encrypted_packets:
            print(f'📊 RESULTS:')
            print(f'   • VPN encrypted packets: {len(encrypted_packets)}')
            
            # Show sample packets
            print(f'\n🔍 SAMPLE PACKETS (first 3):')
            for i, pkt in enumerate(encrypted_packets[:3]):
                print(f'   {i+1}. {pkt["src_ip"]}:{pkt["src_port"]} → {pkt["dst_ip"]}:{pkt["dst_port"]}')
                print(f'      {pkt["protocol"]}, {pkt["data_length"]} bytes')
                print(f'      {pkt["hex_data"][:60]}...')
                print()
            
            return len(encrypted_packets)
        else:
            print('❌ No encrypted data found')
            return 0
            
    except Exception as e:
        print(f'❌ Error: {str(e)}')
        return 0

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    else:
        pcap_file = input("Enter PCAP file path: ").strip()
    
    if os.path.exists(pcap_file):
        count = extract_encrypted_data(pcap_file)
        
        if count > 0:
            print(f'\n🎉 SUCCESS: {count} encrypted packets extracted!')
        else:
            print('\n❌ No encrypted data available')
    else:
        print(f'❌ File not found: {pcap_file}')
