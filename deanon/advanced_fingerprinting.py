#!/usr/bin/env python3
"""
Advanced Network Fingerprinting Module
Implements sophisticated device and behavior fingerprinting techniques
for network forensics and security analysis.
"""

import hashlib
import statistics
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional
from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw, Ether
import re
import time

class AdvancedFingerprinter:
    """Advanced network fingerprinting for device identification and behavior analysis"""
    
    def __init__(self):
        self.fingerprints = {}
        self.behavioral_patterns = {}
        self.timing_patterns = {}
        
    def extract_comprehensive_fingerprint(self, pcap_file: str) -> Dict:
        """Extract comprehensive device and behavioral fingerprints"""
        try:
            packets = rdpcap(pcap_file)
            results = {
                'device_fingerprints': {},
                'behavioral_patterns': {},
                'timing_analysis': {},
                'protocol_signatures': {},
                'application_fingerprints': {}
            }
            
            # Process packets for comprehensive analysis
            ip_data = defaultdict(lambda: {
                'packets': [],
                'protocols': set(),
                'ports': set(),
                'packet_sizes': [],
                'inter_arrival_times': [],
                'tcp_options': set(),
                'user_agents': set(),
                'dns_queries': set(),
                'tls_fingerprints': set()
            })
            
            prev_time = None
            for pkt in packets:
                if IP in pkt:
                    src_ip = pkt[IP].src
                    current_time = float(pkt.time)
                    
                    # Collect packet data
                    ip_data[src_ip]['packets'].append(pkt)
                    ip_data[src_ip]['packet_sizes'].append(len(pkt))
                    
                    # Calculate inter-arrival times
                    if prev_time:
                        ip_data[src_ip]['inter_arrival_times'].append(current_time - prev_time)
                    prev_time = current_time
                    
                    # Protocol analysis
                    if TCP in pkt:
                        ip_data[src_ip]['protocols'].add('TCP')
                        ip_data[src_ip]['ports'].add(pkt[TCP].dport)
                        
                        # TCP options fingerprinting
                        if hasattr(pkt[TCP], 'options'):
                            for option in pkt[TCP].options:
                                ip_data[src_ip]['tcp_options'].add(str(option))
                    
                    elif UDP in pkt:
                        ip_data[src_ip]['protocols'].add('UDP')
                        ip_data[src_ip]['ports'].add(pkt[UDP].dport)
                        
                        # DNS analysis
                        if pkt[UDP].dport == 53 and DNS in pkt:
                            if pkt[DNS].qd:
                                query = str(pkt[DNS].qd.qname, 'utf-8').rstrip('.')
                                ip_data[src_ip]['dns_queries'].add(query)
                    
                    # HTTP User-Agent extraction
                    if Raw in pkt:
                        payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                        user_agent_match = re.search(r'User-Agent: ([^\r\n]+)', payload)
                        if user_agent_match:
                            ip_data[src_ip]['user_agents'].add(user_agent_match.group(1))
            
            # Generate fingerprints for each IP
            for ip, data in ip_data.items():
                results['device_fingerprints'][ip] = self._generate_device_fingerprint(ip, data)
                results['behavioral_patterns'][ip] = self._analyze_behavioral_patterns(data)
                results['timing_analysis'][ip] = self._analyze_timing_patterns(data)
                results['protocol_signatures'][ip] = self._generate_protocol_signature(data)
                results['application_fingerprints'][ip] = self._identify_applications(data)
            
            return results
            
        except Exception as e:
            return {'error': f"Advanced fingerprinting failed: {str(e)}"}
    
    def analyze_advanced_fingerprints(self, pcap_file: str) -> Dict:
        """Main analysis function called by GUI"""
        self.pcap_file = pcap_file  # Store pcap_file as instance attribute
        return self.extract_comprehensive_fingerprint(pcap_file)
    
    def _generate_device_fingerprint(self, ip: str, data: Dict) -> Dict:
        """Generate comprehensive device fingerprint"""
        if not data['packets']:
            return {'error': 'No packets for fingerprinting'}
        
        first_pkt = data['packets'][0]
        fingerprint = {
            'ip': ip,
            'ttl': first_pkt[IP].ttl if IP in first_pkt else None,
            'os_guess': self._guess_os_advanced(first_pkt, data),
            'tcp_window_size': first_pkt[TCP].window if TCP in first_pkt else None,
            'mss': self._extract_mss(first_pkt),
            'tcp_options_signature': self._generate_tcp_options_signature(data['tcp_options']),
            'packet_size_distribution': self._analyze_packet_sizes(data['packet_sizes']),
            'protocol_preference': list(data['protocols']),
            'port_usage_pattern': self._analyze_port_usage(data['ports']),
            'unique_signature': self._generate_unique_signature(ip, data)
        }
        
        return fingerprint
    
    def _analyze_behavioral_patterns(self, data: Dict) -> Dict:
        """Analyze behavioral patterns for user identification"""
        patterns = {
            'activity_rhythm': self._analyze_activity_rhythm(data['inter_arrival_times']),
            'browsing_pattern': self._analyze_browsing_pattern(data['dns_queries']),
            'application_usage': self._analyze_application_usage(data['ports']),
            'communication_style': self._analyze_communication_style(data['packet_sizes']),
            'session_characteristics': self._analyze_session_characteristics(data['packets'])
        }
        
        return patterns
    
    def _analyze_timing_patterns(self, data: Dict) -> Dict:
        """Analyze timing patterns for correlation attacks"""
        if not data['inter_arrival_times']:
            return {'error': 'No timing data available'}
        
        times = data['inter_arrival_times']
        timing_analysis = {
            'mean_interval': statistics.mean(times),
            'median_interval': statistics.median(times),
            'std_deviation': statistics.stdev(times) if len(times) > 1 else 0,
            'burst_detection': self._detect_bursts(times),
            'periodicity': self._detect_periodicity(times),
            'timing_signature': self._generate_timing_signature(times)
        }
        
        return timing_analysis
    
    def _generate_protocol_signature(self, data: Dict) -> Dict:
        """Generate protocol usage signature"""
        signature = {
            'protocol_distribution': dict(Counter(data['protocols'])),
            'port_frequency': dict(Counter(data['ports'])),
            'protocol_sequence': self._analyze_protocol_sequence(data['packets']),
            'encryption_usage': self._detect_encryption_usage(data['ports'])
        }
        
        return signature
    
    def _identify_applications(self, data: Dict) -> Dict:
        """Identify applications and services used"""
        applications = {
            'web_browsers': self._identify_browsers(data['user_agents']),
            'messaging_apps': self._identify_messaging_apps(data['ports']),
            'streaming_services': self._identify_streaming(data['ports'], data['packet_sizes']),
            'file_sharing': self._identify_file_sharing(data['ports']),
            'vpn_clients': self._identify_vpn_clients(data['ports'], data['protocols'])
        }
        
        return applications
    
    def _guess_os_advanced(self, pkt, data: Dict) -> str:
        """Advanced OS detection using multiple indicators"""
        if not IP in pkt:
            return "Unknown"
        
        ttl = pkt[IP].ttl
        tcp_window = pkt[TCP].window if TCP in pkt else None
        
        # Advanced OS fingerprinting
        if ttl >= 128:
            if tcp_window == 65535:
                return "Windows 10/11"
            elif tcp_window == 8192:
                return "Windows 7/8"
            else:
                return "Windows (Unknown version)"
        elif ttl >= 64:
            if tcp_window == 65535:
                return "macOS"
            elif tcp_window in [5840, 14600]:
                return "Linux (Ubuntu/Debian)"
            else:
                return "Linux/Unix"
        elif ttl >= 32:
            return "Old Unix/Legacy system"
        else:
            return "Unknown/Modified OS"
    
    def _extract_mss(self, pkt) -> Optional[int]:
        """Extract Maximum Segment Size from TCP options"""
        if TCP in pkt and hasattr(pkt[TCP], 'options'):
            for option in pkt[TCP].options:
                if option[0] == 'MSS':
                    return option[1]
        return None
    
    def _generate_tcp_options_signature(self, tcp_options: set) -> str:
        """Generate TCP options fingerprint"""
        if not tcp_options:
            return "No TCP options"
        
        options_list = sorted(list(tcp_options))
        signature = hashlib.md5(str(options_list).encode()).hexdigest()[:8]
        return f"TCP_OPT_{signature}"
    
    def _analyze_packet_sizes(self, sizes: List[int]) -> Dict:
        """Analyze packet size distribution"""
        if not sizes:
            return {'error': 'No packet sizes'}
        
        return {
            'mean_size': statistics.mean(sizes),
            'median_size': statistics.median(sizes),
            'size_variance': statistics.variance(sizes) if len(sizes) > 1 else 0,
            'common_sizes': dict(Counter(sizes).most_common(5)),
            'mtu_detection': self._detect_mtu(sizes)
        }
    
    def _analyze_port_usage(self, ports: set) -> Dict:
        """Analyze port usage patterns"""
        port_categories = {
            'web': [80, 443, 8080, 8443],
            'email': [25, 110, 143, 993, 995],
            'file_transfer': [20, 21, 22, 989, 990],
            'messaging': [1863, 5222, 5223, 6667],
            'vpn': [1194, 4500, 500, 1723],
            'p2p': [6881, 6889, 4662, 4672]
        }
        
        usage_pattern = {}
        for category, category_ports in port_categories.items():
            usage_pattern[category] = len(ports.intersection(set(category_ports)))
        
        return usage_pattern
    
    def _generate_unique_signature(self, ip: str, data: Dict) -> str:
        """Generate unique device signature"""
        signature_data = {
            'protocols': sorted(list(data['protocols'])),
            'top_ports': sorted(list(data['ports']))[:10],
            'packet_count': len(data['packets']),
            'avg_packet_size': statistics.mean(data['packet_sizes']) if data['packet_sizes'] else 0
        }
        
        signature_string = f"{ip}_{str(signature_data)}"
        return hashlib.sha256(signature_string.encode()).hexdigest()[:16]
    
    def _analyze_activity_rhythm(self, intervals: List[float]) -> Dict:
        """Analyze user activity rhythm"""
        if not intervals:
            return {'pattern': 'No activity data'}
        
        # Detect activity patterns
        short_intervals = [i for i in intervals if i < 1.0]  # < 1 second
        medium_intervals = [i for i in intervals if 1.0 <= i < 10.0]  # 1-10 seconds
        long_intervals = [i for i in intervals if i >= 10.0]  # > 10 seconds
        
        return {
            'rapid_activity': len(short_intervals),
            'normal_activity': len(medium_intervals),
            'idle_periods': len(long_intervals),
            'activity_pattern': 'burst' if len(short_intervals) > len(long_intervals) else 'steady'
        }
    
    def _analyze_browsing_pattern(self, dns_queries: set) -> Dict:
        """Analyze browsing patterns from DNS queries"""
        if not dns_queries:
            return {'pattern': 'No DNS data'}
        
        domains = list(dns_queries)
        social_media = ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com']
        news_sites = ['cnn.com', 'bbc.com', 'reuters.com', 'nytimes.com']
        tech_sites = ['github.com', 'stackoverflow.com', 'reddit.com']
        
        pattern = {
            'total_domains': len(domains),
            'social_media_usage': len([d for d in domains if any(sm in d for sm in social_media)]),
            'news_consumption': len([d for d in domains if any(ns in d for ns in news_sites)]),
            'tech_interest': len([d for d in domains if any(ts in d for ts in tech_sites)]),
            'unique_domains': len(set(domains))
        }
        
        return pattern
    
    def _detect_bursts(self, intervals: List[float]) -> Dict:
        """Detect burst patterns in traffic"""
        if len(intervals) < 10:
            return {'bursts_detected': 0}
        
        # Simple burst detection: consecutive short intervals
        burst_threshold = 0.1  # 100ms
        bursts = 0
        in_burst = False
        
        for interval in intervals:
            if interval < burst_threshold:
                if not in_burst:
                    bursts += 1
                    in_burst = True
            else:
                in_burst = False
        
        return {
            'bursts_detected': bursts,
            'burst_intensity': bursts / len(intervals) if intervals else 0
        }
    
    def _detect_periodicity(self, intervals: List[float]) -> Dict:
        """Detect periodic patterns in timing"""
        if len(intervals) < 20:
            return {'periodic': False}
        
        # Simple periodicity detection
        rounded_intervals = [round(i, 1) for i in intervals]
        most_common = Counter(rounded_intervals).most_common(1)[0]
        
        return {
            'periodic': most_common[1] > len(intervals) * 0.3,
            'dominant_interval': most_common[0],
            'frequency': most_common[1]
        }
    
    def _generate_timing_signature(self, intervals: List[float]) -> str:
        """Generate timing-based signature"""
        if not intervals:
            return "NO_TIMING"
        
        # Create signature from timing characteristics
        mean_time = statistics.mean(intervals)
        signature_data = f"{mean_time:.3f}_{len(intervals)}"
        return hashlib.md5(signature_data.encode()).hexdigest()[:8]
    
    def _analyze_protocol_sequence(self, packets: List) -> List[str]:
        """Analyze protocol usage sequence"""
        sequence = []
        for pkt in packets[:50]:  # First 50 packets
            if TCP in pkt:
                sequence.append(f"TCP:{pkt[TCP].dport}")
            elif UDP in pkt:
                sequence.append(f"UDP:{pkt[UDP].dport}")
            else:
                sequence.append("OTHER")
        return sequence
    
    def _detect_encryption_usage(self, ports: set) -> Dict:
        """Detect encryption usage patterns"""
        encrypted_ports = {443, 993, 995, 465, 587, 22}
        unencrypted_ports = {80, 110, 143, 25, 21, 23}
        
        encrypted_count = len(ports.intersection(encrypted_ports))
        unencrypted_count = len(ports.intersection(unencrypted_ports))
        
        return {
            'encrypted_connections': encrypted_count,
            'unencrypted_connections': unencrypted_count,
            'encryption_preference': encrypted_count > unencrypted_count
        }
    
    def _identify_browsers(self, user_agents: set) -> List[str]:
        """Identify web browsers from User-Agent strings"""
        browsers = []
        for ua in user_agents:
            if 'Chrome' in ua:
                browsers.append('Chrome')
            elif 'Firefox' in ua:
                browsers.append('Firefox')
            elif 'Safari' in ua and 'Chrome' not in ua:
                browsers.append('Safari')
            elif 'Edge' in ua:
                browsers.append('Edge')
        return list(set(browsers))
    
    def _identify_messaging_apps(self, ports: set) -> List[str]:
        """Identify messaging applications"""
        messaging_ports = {
            5222: 'XMPP/Jabber',
            5223: 'XMPP/Jabber (SSL)',
            1863: 'MSN Messenger',
            6667: 'IRC'
        }
        
        apps = []
        for port in ports:
            if port in messaging_ports:
                apps.append(messaging_ports[port])
        return apps
    
    def _identify_streaming(self, ports: set, packet_sizes: List[int]) -> Dict:
        """Identify streaming services"""
        streaming_indicators = {
            'large_packets': len([s for s in packet_sizes if s > 1400]) > len(packet_sizes) * 0.5,
            'streaming_ports': bool(ports.intersection({1935, 554, 8080})),
            'likely_streaming': False
        }
        
        streaming_indicators['likely_streaming'] = (
            streaming_indicators['large_packets'] or 
            streaming_indicators['streaming_ports']
        )
        
        return streaming_indicators
    
    def _identify_file_sharing(self, ports: set) -> List[str]:
        """Identify file sharing applications"""
        p2p_ports = {
            6881: 'BitTorrent',
            4662: 'eMule',
            4672: 'eMule',
            1214: 'Kazaa'
        }
        
        apps = []
        for port in ports:
            if port in p2p_ports:
                apps.append(p2p_ports[port])
        return apps
    
    def _identify_vpn_clients(self, ports: set, protocols: set) -> Dict:
        """Identify VPN client characteristics"""
        vpn_indicators = {
            'openvpn_port': 1194 in ports,
            'ipsec_ports': bool(ports.intersection({500, 4500})),
            'pptp_port': 1723 in ports,
            'encrypted_traffic': 'TCP' in protocols and any(p in ports for p in [443, 993, 995])
        }
        
        vpn_indicators['vpn_likely'] = any(vpn_indicators.values())
        return vpn_indicators
    
    def _detect_mtu(self, sizes: List[int]) -> int:
        """Detect Maximum Transmission Unit"""
        if not sizes:
            return 1500  # Default MTU
        
        # Find the most common large packet size
        large_packets = [s for s in sizes if s > 1000]
        if large_packets:
            return max(set(large_packets), key=large_packets.count)
        return 1500
    
    def _analyze_application_usage(self, ports: set) -> Dict:
        """Analyze application usage patterns from port data"""
        if not ports:
            return {'usage_pattern': 'No port data'}
        
        # Categorize applications by port usage
        app_categories = {
            'web_browsing': len(ports.intersection({80, 443, 8080, 8443})),
            'email_clients': len(ports.intersection({25, 110, 143, 993, 995, 465, 587})),
            'file_transfer': len(ports.intersection({20, 21, 22, 989, 990, 115})),
            'messaging': len(ports.intersection({1863, 5222, 5223, 6667, 194})),
            'media_streaming': len(ports.intersection({1935, 554, 8080, 1755})),
            'gaming': len(ports.intersection({27015, 7777, 25565, 3724})),
            'vpn_usage': len(ports.intersection({1194, 500, 4500, 1723})),
            'p2p_sharing': len(ports.intersection({6881, 6889, 4662, 4672, 1214})),
            'remote_access': len(ports.intersection({3389, 5900, 22, 23, 5938})),
            'database': len(ports.intersection({3306, 5432, 1433, 1521, 27017}))
        }
        
        # Determine primary usage pattern
        max_category = max(app_categories.items(), key=lambda x: x[1])
        total_identified = sum(app_categories.values())
        
        usage_analysis = {
            'primary_usage': max_category[0] if max_category[1] > 0 else 'unknown',
            'usage_diversity': len([cat for cat, count in app_categories.items() if count > 0]),
            'total_identified_ports': total_identified,
            'unidentified_ports': len(ports) - total_identified,
            'application_categories': app_categories,
            'usage_intensity': total_identified / len(ports) if ports else 0
        }
        
        # Behavioral insights
        if app_categories['web_browsing'] > 0 and app_categories['media_streaming'] > 0:
            usage_analysis['behavior_type'] = 'multimedia_consumer'
        elif app_categories['file_transfer'] > 0 and app_categories['remote_access'] > 0:
            usage_analysis['behavior_type'] = 'technical_user'
        elif app_categories['gaming'] > 0:
            usage_analysis['behavior_type'] = 'gamer'
        elif app_categories['p2p_sharing'] > 0:
            usage_analysis['behavior_type'] = 'file_sharer'
        elif app_categories['vpn_usage'] > 0:
            usage_analysis['behavior_type'] = 'privacy_conscious'
        else:
            usage_analysis['behavior_type'] = 'general_user'
        
        return usage_analysis
    
    def _analyze_communication_style(self, packet_sizes: List[int]) -> Dict:
        """Analyze communication style from packet size patterns"""
        if not packet_sizes:
            return {'style': 'No data'}
        
        # Analyze packet size distribution
        small_packets = len([s for s in packet_sizes if s < 100])  # Control packets
        medium_packets = len([s for s in packet_sizes if 100 <= s < 1000])  # Text/small data
        large_packets = len([s for s in packet_sizes if s >= 1000])  # Media/files
        
        total_packets = len(packet_sizes)
        
        communication_style = {
            'small_packet_ratio': small_packets / total_packets if total_packets > 0 else 0,
            'medium_packet_ratio': medium_packets / total_packets if total_packets > 0 else 0,
            'large_packet_ratio': large_packets / total_packets if total_packets > 0 else 0,
            'avg_packet_size': statistics.mean(packet_sizes),
            'packet_size_variance': statistics.variance(packet_sizes) if len(packet_sizes) > 1 else 0
        }
        
        # Determine communication style
        if communication_style['large_packet_ratio'] > 0.6:
            communication_style['style'] = 'bulk_transfer'
        elif communication_style['small_packet_ratio'] > 0.7:
            communication_style['style'] = 'interactive'
        elif communication_style['medium_packet_ratio'] > 0.5:
            communication_style['style'] = 'mixed_usage'
        else:
            communication_style['style'] = 'balanced'
        
        return communication_style
    
    def _analyze_session_characteristics(self, packets: List) -> Dict:
        """Analyze session-level characteristics"""
        if not packets:
            return {'characteristics': 'No session data'}
        
        # Basic session analysis
        tcp_packets = [pkt for pkt in packets if TCP in pkt]
        udp_packets = [pkt for pkt in packets if UDP in pkt]
        
        session_chars = {
            'total_packets': len(packets),
            'tcp_packets': len(tcp_packets),
            'udp_packets': len(udp_packets),
            'session_duration': 0,
            'connection_attempts': 0,
            'established_connections': 0
        }
        
        # Calculate session duration
        if len(packets) > 1:
            start_time = float(packets[0].time)
            end_time = float(packets[-1].time)
            session_chars['session_duration'] = end_time - start_time
        
        # Analyze TCP connections
        syn_packets = len([pkt for pkt in tcp_packets if TCP in pkt and pkt[TCP].flags & 0x02])  # SYN flag
        ack_packets = len([pkt for pkt in tcp_packets if TCP in pkt and pkt[TCP].flags & 0x10])  # ACK flag
        
        session_chars['connection_attempts'] = syn_packets
        session_chars['established_connections'] = min(syn_packets, ack_packets)
        
        # Session behavior classification
        if session_chars['session_duration'] > 3600:  # > 1 hour
            session_chars['session_type'] = 'long_session'
        elif session_chars['session_duration'] > 300:  # > 5 minutes
            session_chars['session_type'] = 'medium_session'
        else:
            session_chars['session_type'] = 'short_session'
        
        return session_chars

def analyze_advanced_fingerprints(pcap_file: str) -> Dict:
    """Main function to perform advanced fingerprinting analysis"""
    fingerprinter = AdvancedFingerprinter()
    return fingerprinter.extract_comprehensive_fingerprint(pcap_file)
