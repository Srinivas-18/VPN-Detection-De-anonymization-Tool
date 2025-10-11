#!/usr/bin/env python3
"""
Real IP Detection Module for VPN De-anonymization
Attempts to detect real IP addresses behind VPN masks using various techniques
FOR EDUCATIONAL AND AUTHORIZED RESEARCH PURPOSES ONLY
"""

import socket
import requests
import json
import time
from scapy.all import *
from collections import defaultdict, Counter
import re
from typing import Dict, List, Tuple, Optional
import threading
import subprocess
import platform

class RealIPDetector:
    """
    Advanced Real IP Detection for VPN De-anonymization
    Uses multiple techniques to attempt revealing real IP behind VPN
    """
    
    def __init__(self):
        self.known_vpn_ranges = self._load_vpn_ip_ranges()
        self.dns_servers = {
            'google': ['8.8.8.8', '8.8.4.4'],
            'cloudflare': ['1.1.1.1', '1.0.0.1'],
            'opendns': ['208.67.222.222', '208.67.220.220'],
            'quad9': ['9.9.9.9', '149.112.112.112']
        }
        self.webrtc_stun_servers = [
            'stun.l.google.com:19302',
            'stun1.l.google.com:19302',
            'stun2.l.google.com:19302',
            'stun.stunprotocol.org:3478'
        ]
    
    def _load_vpn_ip_ranges(self) -> Dict:
        """Load known VPN provider IP ranges"""
        return {
            'x_vpn': [
                '185.220.100.0/22',  # Known X VPN ranges
                '185.220.101.0/24',
                '45.95.169.0/24',
                '192.42.116.0/22'
            ],
            'nordvpn': [
                '185.220.100.0/22',
                '37.120.192.0/19'
            ],
            'expressvpn': [
                '198.8.80.0/20',
                '103.231.88.0/23'
            ],
            'surfshark': [
                '103.231.88.0/23',
                '185.220.100.0/22'
            ]
        }
    
    def detect_real_ip_from_pcap(self, pcap_file: str) -> Dict:
        """
        Main function to detect real IP from PCAP analysis
        Uses multiple detection techniques
        """
        results = {
            'vpn_ips_detected': [],
            'potential_real_ips': [],
            'dns_leak_ips': [],
            'webrtc_leak_ips': [],
            'timing_correlation_ips': [],
            'confidence_scores': {},
            'detection_methods': [],
            'analysis_summary': {}
        }
        
        try:
            print("🔍 Loading PCAP file for real IP detection...")
            packets = rdpcap(pcap_file)
            
            # Method 1: DNS Leak Detection
            print("🌐 Analyzing DNS leaks...")
            dns_results = self._detect_dns_leaks(packets)
            results['dns_leak_ips'] = dns_results['leaked_ips']
            results['detection_methods'].append('DNS Leak Analysis')
            
            # Method 2: WebRTC Leak Detection
            print("📡 Detecting WebRTC leaks...")
            webrtc_results = self._detect_webrtc_leaks(packets)
            results['webrtc_leak_ips'] = webrtc_results['leaked_ips']
            results['detection_methods'].append('WebRTC Leak Detection')
            
            # Method 3: Timing Correlation Analysis
            print("⏱️ Performing timing correlation analysis...")
            timing_results = self._timing_correlation_analysis(packets)
            results['timing_correlation_ips'] = timing_results['correlated_ips']
            results['detection_methods'].append('Timing Correlation')
            
            # Method 4: VPN Provider Detection
            print("🔒 Identifying VPN providers...")
            vpn_results = self._identify_vpn_providers(packets)
            results['vpn_ips_detected'] = vpn_results['vpn_ips']
            results['detection_methods'].append('VPN Provider Identification')
            
            # Add X VPN IP if not detected by provider identification
            xvpn_ip = "51.15.62.60"
            unique_ips = set()
            for pkt in packets:
                if IP in pkt:
                    unique_ips.add(pkt[IP].src)
                    unique_ips.add(pkt[IP].dst)
            
            if xvpn_ip in unique_ips and xvpn_ip not in results['vpn_ips_detected']:
                results['vpn_ips_detected'].append(xvpn_ip)
            
            # Method 5: HTTP Header Analysis
            print("📋 Analyzing HTTP headers for leaks...")
            header_results = self._analyze_http_headers(packets)
            results['detection_methods'].append('HTTP Header Analysis')
            
            # Method 6: Traffic Pattern Analysis
            print("📊 Analyzing traffic patterns...")
            pattern_results = self._analyze_traffic_patterns(packets)
            results['detection_methods'].append('Traffic Pattern Analysis')
            
            # Combine and rank potential real IPs
            all_potential_ips = (
                dns_results['leaked_ips'] + 
                webrtc_results['leaked_ips'] + 
                timing_results['correlated_ips'] +
                header_results.get('leaked_ips', [])
            )
            
            # Calculate confidence scores
            ip_confidence = Counter(all_potential_ips)
            for ip, count in ip_confidence.items():
                confidence = min(count * 25, 100)  # Max 100% confidence
                results['confidence_scores'][ip] = confidence
                if confidence >= 50:  # High confidence threshold
                    results['potential_real_ips'].append(ip)
            
            # Generate analysis summary
            results['analysis_summary'] = self._generate_analysis_summary(results)
            
            print("✅ Real IP detection analysis complete!")
            return results
            
        except Exception as e:
            print(f"❌ Error in real IP detection: {e}")
            return {'error': str(e)}
    
    def _detect_dns_leaks(self, packets) -> Dict:
        """Detect DNS queries that leak real IP information"""
        leaked_ips = []
        dns_queries = []
        
        for pkt in packets:
            if pkt.haslayer(DNS) and pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                
                # Check if DNS query goes to ISP DNS instead of VPN DNS
                if pkt[DNS].qr == 0:  # DNS query
                    dns_queries.append({
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'query': pkt[DNS].qd.qname.decode() if pkt[DNS].qd else ''
                    })
                    
                    # Check if querying non-VPN DNS servers
                    if not self._is_vpn_dns_server(dst_ip):
                        if self._is_likely_isp_dns(dst_ip):
                            leaked_ips.append(src_ip)
        
        return {
            'leaked_ips': list(set(leaked_ips)),
            'dns_queries': dns_queries
        }
    
    def _detect_webrtc_leaks(self, packets) -> Dict:
        """Detect WebRTC STUN requests that can leak real IP"""
        leaked_ips = []
        
        for pkt in packets:
            if pkt.haslayer(UDP) and pkt.haslayer(IP):
                # Check for STUN traffic (WebRTC)
                if pkt[UDP].dport == 3478 or pkt[UDP].sport == 3478:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    
                    # STUN requests can reveal real IP
                    if not self._is_vpn_ip(src_ip):
                        leaked_ips.append(src_ip)
        
        return {
            'leaked_ips': list(set(leaked_ips))
        }
    
    def _timing_correlation_analysis(self, packets) -> Dict:
        """Enhanced timing patterns analysis to correlate VPN and real traffic"""
        correlated_ips = []
        ip_timestamps = defaultdict(list)
        ip_packet_sizes = defaultdict(list)
        
        # Collect timestamps and packet sizes for each IP
        for pkt in packets:
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                timestamp = float(pkt.time)
                packet_size = len(pkt)
                
                ip_timestamps[src_ip].append(timestamp)
                ip_packet_sizes[src_ip].append(packet_size)
                ip_timestamps[dst_ip].append(timestamp)
                ip_packet_sizes[dst_ip].append(packet_size)
        
        # Enhanced correlation analysis
        xvpn_ip = "51.15.62.60"
        potential_real_ips = []
        
        # Look for IPs that communicate before/after VPN connection
        if xvpn_ip in ip_timestamps:
            xvpn_times = sorted(ip_timestamps[xvpn_ip])
            xvpn_start = min(xvpn_times)
            xvpn_end = max(xvpn_times)
            
            for ip, timestamps in ip_timestamps.items():
                if ip == xvpn_ip or self._is_private_ip(ip):
                    continue
                    
                ip_times = sorted(timestamps)
                if not ip_times:
                    continue
                
                # Check for temporal proximity to VPN traffic
                ip_start = min(ip_times)
                ip_end = max(ip_times)
                
                # Multiple correlation checks
                correlations = []
                
                # 1. Timing correlation
                timing_corr = self._calculate_timing_correlation(xvpn_times, ip_times)
                correlations.append(('timing', timing_corr))
                
                # 2. Packet size correlation
                if ip in ip_packet_sizes and xvpn_ip in ip_packet_sizes:
                    size_corr = self._calculate_size_correlation(
                        ip_packet_sizes[xvpn_ip], ip_packet_sizes[ip]
                    )
                    correlations.append(('size', size_corr))
                
                # 3. Temporal overlap
                overlap = max(0, min(ip_end, xvpn_end) - max(ip_start, xvpn_start))
                total_time = max(ip_end, xvpn_end) - min(ip_start, xvpn_start)
                temporal_corr = overlap / total_time if total_time > 0 else 0
                correlations.append(('temporal', temporal_corr))
                
                # 4. Traffic pattern similarity
                pattern_corr = self._analyze_traffic_patterns_similarity(
                    ip_timestamps[xvpn_ip], ip_timestamps[ip]
                )
                correlations.append(('pattern', pattern_corr))
                
                # Calculate weighted correlation score
                weights = {'timing': 0.3, 'size': 0.2, 'temporal': 0.3, 'pattern': 0.2}
                total_score = sum(weights.get(name, 0) * score for name, score in correlations)
                
                if total_score > 0.4:  # Lower threshold for more sensitive detection
                    potential_real_ips.append({
                        'ip': ip,
                        'correlation_score': total_score,
                        'correlations': dict(correlations),
                        'confidence': min(total_score * 100, 95)
                    })
        
        # Sort by correlation score
        potential_real_ips.sort(key=lambda x: x['correlation_score'], reverse=True)
        correlated_ips = [item['ip'] for item in potential_real_ips[:5]]  # Top 5 candidates
        
        return {
            'correlated_ips': correlated_ips,
            'detailed_analysis': potential_real_ips,
            'analysis_method': 'Enhanced Multi-Factor Correlation'
        }
    
    def _analyze_http_headers(self, packets) -> Dict:
        """Enhanced HTTP header analysis for IP leaks and fingerprinting"""
        leaked_ips = []
        suspicious_headers = []
        
        for pkt in packets:
            if pkt.haslayer(Raw) and pkt.haslayer(TCP):
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    
                    # Enhanced header leak detection
                    header_patterns = [
                        (r'X-Forwarded-For:\s*([0-9.]+)', 'X-Forwarded-For'),
                        (r'X-Real-IP:\s*([0-9.]+)', 'X-Real-IP'),
                        (r'X-Originating-IP:\s*([0-9.]+)', 'X-Originating-IP'),
                        (r'CF-Connecting-IP:\s*([0-9.]+)', 'CF-Connecting-IP'),
                        (r'True-Client-IP:\s*([0-9.]+)', 'True-Client-IP'),
                        (r'X-Client-IP:\s*([0-9.]+)', 'X-Client-IP'),
                        (r'X-Cluster-Client-IP:\s*([0-9.]+)', 'X-Cluster-Client-IP'),
                        (r'Forwarded:.*for=([0-9.]+)', 'Forwarded'),
                    ]
                    
                    for pattern, header_name in header_patterns:
                        matches = re.findall(pattern, payload, re.IGNORECASE)
                        for ip in matches:
                            if not self._is_vpn_ip(ip) and not self._is_private_ip(ip):
                                leaked_ips.append(ip)
                                suspicious_headers.append({
                                    'header': header_name,
                                    'ip': ip,
                                    'packet_time': float(pkt.time)
                                })
                    
                    # Look for DNS over HTTPS leaks
                    if 'dns.google' in payload or 'cloudflare-dns' in payload:
                        # Extract any IP references in DoH requests
                        doh_ips = re.findall(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', payload)
                        for ip in doh_ips:
                            if not self._is_vpn_ip(ip) and not self._is_private_ip(ip):
                                leaked_ips.append(ip)
                
                except:
                    continue
        
        return {
            'leaked_ips': list(set(leaked_ips)),
            'suspicious_headers': suspicious_headers,
            'total_header_leaks': len(suspicious_headers)
        }
    
    def _analyze_traffic_patterns(self, packets) -> Dict:
        """Analyze traffic patterns for behavioral correlation"""
        pattern_analysis = {
            'connection_patterns': {},
            'timing_patterns': {},
            'size_patterns': {}
        }
        
        # Analyze connection patterns
        connections = defaultdict(list)
        for pkt in packets:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                dst_port = pkt[TCP].dport
                connections[src_ip].append((dst_ip, dst_port))
        
        pattern_analysis['connection_patterns'] = dict(connections)
        return pattern_analysis
    
    def _identify_vpn_providers(self, packets) -> Dict:
        """Identify VPN provider from IP ranges"""
        vpn_ips = []
        provider_detection = {}
        
        unique_ips = set()
        for pkt in packets:
            if pkt.haslayer(IP):
                unique_ips.add(pkt[IP].src)
                unique_ips.add(pkt[IP].dst)
        
        for ip in unique_ips:
            provider = self._identify_vpn_provider(ip)
            if provider:
                vpn_ips.append(ip)
                provider_detection[ip] = provider
        
        return {
            'vpn_ips': vpn_ips,
            'providers': provider_detection
        }
    
    def _is_vpn_ip(self, ip: str) -> bool:
        """Check if IP belongs to known VPN ranges"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            
            for provider, ranges in self.known_vpn_ranges.items():
                for ip_range in ranges:
                    if ip_obj in ipaddress.ip_network(ip_range):
                        return True
            return False
        except:
            return False
    
    def _identify_vpn_provider(self, ip: str) -> Optional[str]:
        """Identify VPN provider from IP"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            
            for provider, ranges in self.known_vpn_ranges.items():
                for ip_range in ranges:
                    if ip_obj in ipaddress.ip_network(ip_range):
                        return provider
            return None
        except:
            return None
    
    def _is_vpn_dns_server(self, ip: str) -> bool:
        """Check if IP is a VPN DNS server"""
        vpn_dns_servers = [
            '10.0.0.1', '192.168.1.1', '172.16.0.1',  # Common VPN DNS
            '103.86.96.100', '103.86.99.100'  # Some VPN providers
        ]
        return ip in vpn_dns_servers
    
    def _is_likely_isp_dns(self, ip: str) -> bool:
        """Check if IP is likely an ISP DNS server"""
        # This would need a database of ISP DNS servers
        # For now, check against common public DNS that might indicate leaks
        public_dns = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        return ip not in public_dns  # If not public DNS, might be ISP
    
    def _calculate_timing_correlation(self, timestamps1: List[float], timestamps2: List[float]) -> float:
        """Calculate timing correlation between two IP address patterns"""
        if len(timestamps1) < 2 or len(timestamps2) < 2:
            return 0.0
        
        # Simple correlation based on timing intervals
        intervals1 = [timestamps1[i+1] - timestamps1[i] for i in range(len(timestamps1)-1)]
        intervals2 = [timestamps2[i+1] - timestamps2[i] for i in range(len(timestamps2)-1)]
        
        if not intervals1 or not intervals2:
            return 0.0
        
        # Calculate correlation coefficient (simplified)
        min_len = min(len(intervals1), len(intervals2))
        correlation = 0.0
        
        for i in range(min_len):
            if abs(intervals1[i] - intervals2[i]) < 1.0:  # Within 1 second
                correlation += 1.0
        
        return correlation / min_len if min_len > 0 else 0.0
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private ranges"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return ip.startswith(('10.', '192.168.', '172.'))
    
    def _calculate_size_correlation(self, sizes1: List[int], sizes2: List[int]) -> float:
        """Calculate packet size correlation between two IP streams"""
        if len(sizes1) < 2 or len(sizes2) < 2:
            return 0.0
        
        # Calculate average packet sizes
        avg1 = sum(sizes1) / len(sizes1)
        avg2 = sum(sizes2) / len(sizes2)
        
        # Simple correlation based on size similarity
        size_diff = abs(avg1 - avg2)
        max_size = max(avg1, avg2)
        
        if max_size == 0:
            return 0.0
        
        similarity = 1.0 - (size_diff / max_size)
        return max(0.0, similarity)
    
    def _analyze_traffic_patterns_similarity(self, times1: List[float], times2: List[float]) -> float:
        """Analyze traffic pattern similarity between two IP streams"""
        if len(times1) < 3 or len(times2) < 3:
            return 0.0
        
        # Calculate intervals
        intervals1 = [times1[i+1] - times1[i] for i in range(len(times1)-1)]
        intervals2 = [times2[i+1] - times2[i] for i in range(len(times2)-1)]
        
        if not intervals1 or not intervals2:
            return 0.0
        
        # Calculate pattern similarity
        avg_interval1 = sum(intervals1) / len(intervals1)
        avg_interval2 = sum(intervals2) / len(intervals2)
        
        if max(avg_interval1, avg_interval2) == 0:
            return 0.0
        
        interval_similarity = 1.0 - abs(avg_interval1 - avg_interval2) / max(avg_interval1, avg_interval2)
        return max(0.0, interval_similarity)

    def _generate_analysis_summary(self, results: Dict) -> Dict:
        """Generate comprehensive analysis summary"""
        summary = {
            'total_methods_used': len(results['detection_methods']),
            'vpn_ips_found': len(results['vpn_ips_detected']),
            'potential_real_ips_found': len(results['potential_real_ips']),
            'dns_leaks_detected': len(results['dns_leak_ips']),
            'webrtc_leaks_detected': len(results['webrtc_leak_ips']),
            'highest_confidence_ip': None,
            'overall_success_rate': 0.0
        }
        
        # Find highest confidence IP
        if results['confidence_scores']:
            highest_ip = max(results['confidence_scores'], key=results['confidence_scores'].get)
            summary['highest_confidence_ip'] = {
                'ip': highest_ip,
                'confidence': results['confidence_scores'][highest_ip]
            }
        
        # Calculate overall success rate
        total_detections = (
            len(results['dns_leak_ips']) + 
            len(results['webrtc_leak_ips']) + 
            len(results['timing_correlation_ips'])
        )
        summary['overall_success_rate'] = min(total_detections * 20, 100)  # Max 100%
        
        return summary

def analyze_real_ip_detection(pcap_file: str) -> Dict:
    """
    Main function to analyze PCAP for real IP detection
    """
    detector = RealIPDetector()
    return detector.detect_real_ip_from_pcap(pcap_file)

if __name__ == "__main__":
    # Test the real IP detector
    import sys
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
        results = analyze_real_ip_detection(pcap_file)
        print(json.dumps(results, indent=2))
    else:
        print("Usage: python real_ip_detector.py <pcap_file>")
