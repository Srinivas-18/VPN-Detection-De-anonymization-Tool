# core/packet_processor.py

from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw
import re
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional

def extract_ips_from_pcap(pcap_path, return_total=False):
    packets = rdpcap(pcap_path)
    ip_set = set()

    for pkt in packets:
        if IP in pkt:
            ip_set.add(pkt[IP].src)
            ip_set.add(pkt[IP].dst)

    ip_list = list(ip_set)

    if return_total:
        return ip_list, len(packets)
    else:
        return ip_list

def analyze_packet_details(pcap_path: str) -> Dict:
    """
    Comprehensive packet analysis including protocols, websites, and potential passwords
    """
    try:
        packets = rdpcap(pcap_path)
        analysis = {
            'total_packets': len(packets),
            'protocol_stats': defaultdict(int),
            'port_stats': defaultdict(int),
            'website_access': defaultdict(set),
            'potential_passwords': [],
            'dns_queries': [],
            'http_requests': [],
            'suspicious_activity': [],
            'ip_protocols': defaultdict(int),
            'packet_sizes': [],
            'connection_pairs': defaultdict(int)
        }
        
        for pkt in packets:
            # Basic packet info
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                protocol = pkt[IP].proto
                packet_size = len(pkt)
                
                analysis['packet_sizes'].append(packet_size)
                analysis['ip_protocols'][protocol] += 1
                analysis['connection_pairs'][f"{src_ip} -> {dst_ip}"] += 1
                
                # TCP Analysis
                if TCP in pkt:
                    analysis['protocol_stats']['TCP'] += 1
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    analysis['port_stats'][f"TCP:{dst_port}"] += 1
                    
                    # HTTP Analysis
                    if dst_port == 80 or dst_port == 443:
                        if Raw in pkt:
                            raw_data = pkt[Raw].load.decode('utf-8', errors='ignore')
                            analysis['http_requests'].append({
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'port': dst_port,
                                'data': raw_data[:200]  # First 200 chars
                            })
                            
                            # Extract potential passwords from HTTP data
                            password_patterns = [
                                r'password[=:]\s*([^\s&]+)',
                                r'passwd[=:]\s*([^\s&]+)',
                                r'pwd[=:]\s*([^\s&]+)',
                                r'pass[=:]\s*([^\s&]+)',
                                r'login[=:]\s*([^\s&]+)',
                                r'user[=:]\s*([^\s&]+)',
                                r'username[=:]\s*([^\s&]+)'
                            ]
                            
                            for pattern in password_patterns:
                                matches = re.findall(pattern, raw_data, re.IGNORECASE)
                                for match in matches:
                                    if len(match) > 3:  # Filter out very short matches
                                        analysis['potential_passwords'].append({
                                            'type': 'HTTP',
                                            'src_ip': src_ip,
                                            'dst_ip': dst_ip,
                                            'field': pattern.split('[')[0],
                                            'value': match[:50]  # Truncate for security
                                        })
                
                # UDP Analysis
                elif UDP in pkt:
                    analysis['protocol_stats']['UDP'] += 1
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                    analysis['port_stats'][f"UDP:{dst_port}"] += 1
                    
                    # DNS Analysis
                    if dst_port == 53:
                        if DNS in pkt and pkt[DNS].qr == 0:  # DNS Query
                            if pkt[DNS].qd:
                                qname = str(pkt[DNS].qd.qname, 'utf-8')
                                if qname.endswith('.'):
                                    qname = qname[:-1]
                                analysis['dns_queries'].append({
                                    'src_ip': src_ip,
                                    'query': qname,
                                    'type': 'DNS Query'
                                })
                                analysis['website_access'][src_ip].add(qname)
                
                # Other protocols
                else:
                    protocol_name = get_protocol_name(protocol)
                    analysis['protocol_stats'][protocol_name] += 1
        
        # Calculate statistics
        analysis['avg_packet_size'] = sum(analysis['packet_sizes']) / len(analysis['packet_sizes']) if analysis['packet_sizes'] else 0
        analysis['top_ports'] = dict(Counter(analysis['port_stats']).most_common(10))
        analysis['top_connections'] = dict(Counter(analysis['connection_pairs']).most_common(10))
        analysis['top_websites'] = {}
        
        # Aggregate website access
        for ip, websites in analysis['website_access'].items():
            for website in websites:
                analysis['top_websites'][website] = analysis['top_websites'].get(website, 0) + 1
        
        analysis['top_websites'] = dict(Counter(analysis['top_websites']).most_common(10))
        
        # Identify suspicious activity
        analysis['suspicious_activity'] = identify_suspicious_activity(analysis)
        
        return dict(analysis)  # Convert defaultdict to regular dict
        
    except Exception as e:
        return {
            'error': f"Packet analysis failed: {str(e)}",
            'total_packets': 0
        }

def get_protocol_name(protocol_num: int) -> str:
    """Convert protocol number to name"""
    protocols = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        8: 'EGP',
        9: 'IGP',
        20: 'HMP',
        27: 'RDP',
        28: 'IRTP',
        29: 'ISO-TP4',
        30: 'NETBLT',
        31: 'MFE-NSP',
        32: 'MERIT-INP',
        33: 'DCCP',
        34: '3PC',
        35: 'IDPR',
        36: 'XTP',
        37: 'DDP',
        38: 'IDPR-CMTP',
        39: 'TP++',
        40: 'IL',
        41: 'IPv6',
        42: 'SDRP',
        43: 'IPv6-Route',
        44: 'IPv6-Frag',
        45: 'IDRP',
        46: 'RSVP',
        47: 'GRE',
        48: 'DSR',
        49: 'BNA',
        50: 'ESP',
        51: 'AH',
        52: 'I-NLSP',
        53: 'SWIPE',
        54: 'NARP',
        55: 'MOBILE',
        56: 'TLSP',
        57: 'SKIP',
        58: 'IPv6-ICMP',
        59: 'IPv6-NoNxt',
        60: 'IPv6-Opts',
        61: 'CFTP',
        62: 'SAT-EXPAK',
        63: 'KRYPTOLAN',
        64: 'RVD',
        65: 'IPPC',
        66: 'SAT-MON',
        67: 'VISA',
        68: 'IPCV',
        69: 'CPNX',
        70: 'CPHB',
        71: 'WSN',
        72: 'PVP',
        73: 'BR-SAT-MON',
        74: 'SUN-ND',
        75: 'WB-MON',
        76: 'WB-EXPAK',
        77: 'ISO-IP',
        78: 'VMTP',
        79: 'SECURE-VMTP',
        80: 'VINES',
        81: 'TTP',
        82: 'NSFNET-IGP',
        83: 'DGP',
        84: 'TCF',
        85: 'EIGRP',
        86: 'OSPFIGP',
        87: 'Sprite-RPC',
        88: 'LARP',
        89: 'MTP',
        90: 'AX.25',
        91: 'IPIP',
        92: 'MICP',
        93: 'SCC-SP',
        94: 'ETHERIP',
        95: 'ENCAP',
        96: 'GMTP',
        97: 'IFMP',
        98: 'PNNI',
        99: 'PIM',
        100: 'ARIS',
        101: 'SCPS',
        102: 'QNX',
        103: 'A/N',
        104: 'IPComp',
        105: 'SNP',
        106: 'Compaq-Peer',
        107: 'IPX-in-IP',
        108: 'VRRP',
        109: 'PGM',
        110: 'L2TP',
        111: 'DDX',
        112: 'IATP',
        113: 'STP',
        114: 'SRP',
        115: 'UTI',
        116: 'SMP',
        117: 'SM',
        118: 'PTP',
        119: 'ISIS',
        120: 'FIRE',
        121: 'CRTP',
        122: 'CRUDP',
        123: 'SSCOPMCE',
        124: 'IPLT',
        125: 'SPS',
        126: 'PIPE',
        127: 'SCTP',
        128: 'FC',
        129: 'RSVP-E2E-IGNORE',
        130: 'Mobility Header',
        131: 'UDPLite',
        132: 'MPLS-in-IP',
        133: 'manet',
        134: 'HIP',
        135: 'Shim6',
        136: 'WESP',
        137: 'ROHC'
    }
    return protocols.get(protocol_num, f'Protocol-{protocol_num}')

def identify_suspicious_activity(analysis: Dict) -> List[Dict]:
    """Identify potentially suspicious network activity"""
    suspicious = []
    
    # Check for unusual ports
    suspicious_ports = [22, 23, 3389, 5900, 1433, 3306, 5432, 6379, 27017]
    for port_info, count in analysis['port_stats'].items():
        port_num = int(port_info.split(':')[1])
        if port_num in suspicious_ports and count > 5:
            suspicious.append({
                'type': 'Suspicious Port Usage',
                'details': f"Port {port_num} used {count} times",
                'severity': 'Medium'
            })
    
    # Check for password attempts
    if len(analysis['potential_passwords']) > 0:
        suspicious.append({
            'type': 'Potential Password Exposure',
            'details': f"Found {len(analysis['potential_passwords'])} potential password fields",
            'severity': 'High'
        })
    
    # Check for unusual packet sizes
    if analysis['packet_sizes']:
        avg_size = analysis['avg_packet_size']
        large_packets = [s for s in analysis['packet_sizes'] if s > avg_size * 3]
        if len(large_packets) > 10:
            suspicious.append({
                'type': 'Unusual Packet Sizes',
                'details': f"Found {len(large_packets)} unusually large packets",
                'severity': 'Low'
            })
    
    # Check for repeated connections
    for connection, count in analysis['connection_pairs'].items():
        if count > 100:  # High connection count
            suspicious.append({
                'type': 'High Connection Frequency',
                'details': f"Connection {connection} repeated {count} times",
                'severity': 'Medium'
            })
    
    return suspicious
