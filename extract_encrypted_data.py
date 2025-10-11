#!/usr/bin/env python3
"""
Encrypted Data Extraction Tool
Extracts and analyzes encrypted payloads from PCAP capture
"""

from scapy.all import rdpcap, IP, TCP, UDP, Raw, TLS
import binascii
import json
import os
from collections import defaultdict

def extract_encrypted_data():
    """Extract all encrypted data from the PCAP file"""
    print("🔒 ENCRYPTED DATA EXTRACTION")
    print("=" * 50)
    
    pcap_file = "data.pcapng"
    
    if not os.path.exists(pcap_file):
        print(f"❌ {pcap_file} not found")
        return
    
    print(f"📦 Loading {pcap_file}...")
    packets = rdpcap(pcap_file)
    
    encrypted_data = {
        'tls_sessions': [],
        'encrypted_payloads': [],
        'vpn_encrypted_data': [],
        'unknown_encrypted': [],
        'statistics': {
            'total_encrypted_packets': 0,
            'tls_packets': 0,
            'vpn_packets': 0,
            'raw_encrypted_packets': 0
        }
    }
    
    xvpn_ip = "51.15.62.60"
    
    print("🔍 Analyzing packets for encrypted content...")
    
    for i, pkt in enumerate(packets):
        if not pkt.haslayer(Raw):
            continue
            
        raw_data = pkt[Raw].load
        
        # Check if packet involves VPN IP
        is_vpn_packet = False
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            is_vpn_packet = (src_ip == xvpn_ip or dst_ip == xvpn_ip)
        
        # Detect TLS/SSL traffic
        if pkt.haslayer(TLS) or is_tls_packet(raw_data):
            encrypted_data['statistics']['tls_packets'] += 1
            
            tls_info = {
                'packet_id': i,
                'timestamp': float(pkt.time),
                'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown',
                'src_port': pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport if pkt.haslayer(UDP) else 0,
                'dst_port': pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else 0,
                'data_length': len(raw_data),
                'encrypted_payload': binascii.hexlify(raw_data[:100]).decode(),  # First 100 bytes
                'is_vpn_related': is_vpn_packet,
                'protocol': 'TLS/SSL'
            }
            
            encrypted_data['tls_sessions'].append(tls_info)
        
        # Check for VPN encrypted traffic
        elif is_vpn_packet:
            encrypted_data['statistics']['vpn_packets'] += 1
            
            vpn_info = {
                'packet_id': i,
                'timestamp': float(pkt.time),
                'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown',
                'src_port': pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport if pkt.haslayer(UDP) else 0,
                'dst_port': pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else 0,
                'data_length': len(raw_data),
                'encrypted_payload': binascii.hexlify(raw_data).decode(),
                'protocol': 'VPN Tunnel',
                'encryption_type': detect_encryption_type(raw_data)
            }
            
            encrypted_data['vpn_encrypted_data'].append(vpn_info)
        
        # Check for other encrypted content
        elif is_likely_encrypted(raw_data):
            encrypted_data['statistics']['raw_encrypted_packets'] += 1
            
            enc_info = {
                'packet_id': i,
                'timestamp': float(pkt.time),
                'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'Unknown',
                'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'Unknown',
                'data_length': len(raw_data),
                'encrypted_payload': binascii.hexlify(raw_data[:50]).decode(),  # First 50 bytes
                'entropy_score': calculate_entropy(raw_data),
                'protocol': 'Unknown Encrypted'
            }
            
            encrypted_data['encrypted_payloads'].append(enc_info)
        
        encrypted_data['statistics']['total_encrypted_packets'] += 1
    
    # Display results
    print(f"\n📊 ENCRYPTION ANALYSIS RESULTS:")
    print("=" * 40)
    
    stats = encrypted_data['statistics']
    print(f"🔒 Total Encrypted Packets: {stats['total_encrypted_packets']}")
    print(f"🌐 TLS/SSL Packets: {stats['tls_packets']}")
    print(f"🛡️ VPN Encrypted Packets: {stats['vpn_packets']}")
    print(f"❓ Other Encrypted Packets: {stats['raw_encrypted_packets']}")
    
    # Show TLS sessions
    if encrypted_data['tls_sessions']:
        print(f"\n🔐 TLS/SSL SESSIONS ({len(encrypted_data['tls_sessions'])}):")
        for i, session in enumerate(encrypted_data['tls_sessions'][:10]):  # Show first 10
            print(f"  {i+1}. {session['src_ip']}:{session['src_port']} → {session['dst_ip']}:{session['dst_port']}")
            print(f"     Length: {session['data_length']} bytes")
            print(f"     VPN Related: {'✅' if session['is_vpn_related'] else '❌'}")
            print(f"     Payload: {session['encrypted_payload'][:50]}...")
            print()
    
    # Show VPN encrypted data
    if encrypted_data['vpn_encrypted_data']:
        print(f"\n🛡️ VPN ENCRYPTED DATA ({len(encrypted_data['vpn_encrypted_data'])}):")
        for i, vpn_data in enumerate(encrypted_data['vpn_encrypted_data'][:5]):  # Show first 5
            print(f"  {i+1}. {vpn_data['src_ip']}:{vpn_data['src_port']} → {vpn_data['dst_ip']}:{vpn_data['dst_port']}")
            print(f"     Length: {vpn_data['data_length']} bytes")
            print(f"     Encryption: {vpn_data['encryption_type']}")
            print(f"     Payload: {vpn_data['encrypted_payload'][:100]}...")
            print()
    
    # Save encrypted data to files
    print(f"\n💾 SAVING ENCRYPTED DATA:")
    
    # Save JSON summary
    with open("encrypted_data_analysis.json", "w") as f:
        json.dump(encrypted_data, f, indent=2)
    print(f"✅ Analysis saved to: encrypted_data_analysis.json")
    
    # Save raw encrypted payloads
    with open("vpn_encrypted_payloads.bin", "wb") as f:
        for vpn_data in encrypted_data['vpn_encrypted_data']:
            payload_bytes = binascii.unhexlify(vpn_data['encrypted_payload'])
            f.write(payload_bytes)
            f.write(b'\n---PACKET_SEPARATOR---\n')
    print(f"✅ VPN payloads saved to: vpn_encrypted_payloads.bin")
    
    # Save TLS data
    if encrypted_data['tls_sessions']:
        with open("tls_encrypted_data.bin", "wb") as f:
            for tls_data in encrypted_data['tls_sessions']:
                payload_bytes = binascii.unhexlify(tls_data['encrypted_payload'])
                f.write(payload_bytes)
                f.write(b'\n---TLS_SEPARATOR---\n')
        print(f"✅ TLS data saved to: tls_encrypted_data.bin")
    
    return encrypted_data

def is_tls_packet(data):
    """Check if data looks like TLS/SSL"""
    if len(data) < 5:
        return False
    
    # TLS record types
    tls_types = [0x14, 0x15, 0x16, 0x17]  # Change cipher, alert, handshake, application data
    
    # Check TLS record header
    if data[0] in tls_types and data[1] == 0x03:  # TLS version starts with 0x03
        return True
    
    return False

def detect_encryption_type(data):
    """Detect encryption type from packet data"""
    if len(data) < 10:
        return "Unknown"
    
    # Check for common encryption signatures
    if is_tls_packet(data):
        return "TLS/SSL"
    elif data[:4] == b'\x00\x00\x00\x00':
        return "Possible OpenVPN"
    elif data[0] in [0x45, 0x46]:  # IP version in encrypted tunnel
        return "Possible IPSec"
    elif calculate_entropy(data) > 7.5:
        return "High Entropy (Likely Encrypted)"
    else:
        return "Unknown/Low Entropy"

def is_likely_encrypted(data):
    """Check if data is likely encrypted based on entropy"""
    if len(data) < 20:
        return False
    
    entropy = calculate_entropy(data)
    return entropy > 7.0  # High entropy suggests encryption

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if len(data) == 0:
        return 0
    
    # Count byte frequencies
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    
    # Calculate entropy
    entropy = 0
    data_len = len(data)
    
    for count in byte_counts:
        if count > 0:
            probability = count / data_len
            entropy -= probability * (probability.bit_length() - 1)
    
    return entropy

def extract_specific_encrypted_streams():
    """Extract specific encrypted streams for analysis"""
    print(f"\n🎯 EXTRACTING SPECIFIC ENCRYPTED STREAMS:")
    print("=" * 45)
    
    pcap_file = "data.pcapng"
    packets = rdpcap(pcap_file)
    xvpn_ip = "51.15.62.60"
    
    # Group packets by connection
    connections = defaultdict(list)
    
    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(Raw):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            if src_ip == xvpn_ip or dst_ip == xvpn_ip:
                if pkt.haslayer(TCP):
                    conn_key = f"{src_ip}:{pkt[TCP].sport}-{dst_ip}:{pkt[TCP].dport}"
                elif pkt.haslayer(UDP):
                    conn_key = f"{src_ip}:{pkt[UDP].sport}-{dst_ip}:{pkt[UDP].dport}"
                else:
                    conn_key = f"{src_ip}-{dst_ip}"
                
                connections[conn_key].append(pkt)
    
    print(f"🔗 Found {len(connections)} VPN connections with encrypted data")
    
    # Extract and save each connection's encrypted data
    for i, (conn_key, pkts) in enumerate(connections.items()):
        if len(pkts) < 5:  # Skip connections with few packets
            continue
            
        print(f"  Connection {i+1}: {conn_key} ({len(pkts)} packets)")
        
        # Save this connection's encrypted data
        filename = f"vpn_connection_{i+1}_encrypted.bin"
        with open(filename, "wb") as f:
            for pkt in pkts:
                if pkt.haslayer(Raw):
                    f.write(pkt[Raw].load)
                    f.write(b'\n---PACKET---\n')
        
        print(f"    💾 Saved to: {filename}")

if __name__ == "__main__":
    encrypted_data = extract_encrypted_data()
    extract_specific_encrypted_streams()
    
    print(f"\n🎉 ENCRYPTED DATA EXTRACTION COMPLETE!")
    print("Files created:")
    print("  • encrypted_data_analysis.json - Analysis summary")
    print("  • vpn_encrypted_payloads.bin - Raw VPN encrypted data")
    print("  • tls_encrypted_data.bin - TLS encrypted sessions")
    print("  • vpn_connection_*_encrypted.bin - Individual VPN connections")
