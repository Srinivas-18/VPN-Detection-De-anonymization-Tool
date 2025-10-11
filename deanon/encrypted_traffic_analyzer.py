#!/usr/bin/env python3
"""
Encrypted Traffic Analysis Module
Analyzes encrypted VPN traffic without breaking encryption.
Uses metadata analysis, traffic patterns, and side-channel attacks.
FOR EDUCATIONAL AND AUTHORIZED RESEARCH PURPOSES ONLY.
"""

import hashlib
import statistics
import numpy as np
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional
from scapy.all import rdpcap, IP, TCP, UDP, Raw
import time
import math

class EncryptedTrafficAnalyzer:
    """Analyzes encrypted VPN traffic using metadata and pattern analysis"""
    
    def __init__(self):
        self.vpn_ports = {
            1194: 'OpenVPN',
            500: 'IPSec/IKE',
            4500: 'IPSec NAT-T',
            1723: 'PPTP',
            1701: 'L2TP',
            443: 'SSL VPN',
            4443: 'SSL VPN Alt',
            8080: 'HTTP Proxy',
            8443: 'HTTPS Proxy'
        }
        
    def analyze_encrypted_traffic(self, pcap_file: str) -> Dict:
        """Comprehensive analysis of encrypted VPN traffic"""
        try:
            packets = rdpcap(pcap_file)
            
            # Extract encrypted flows
            encrypted_flows = self._identify_encrypted_flows(packets)
            
            # Perform various analyses
            results = {
                'encrypted_flows': encrypted_flows,
                'metadata_analysis': self._analyze_metadata(encrypted_flows),
                'traffic_patterns': self._analyze_traffic_patterns(encrypted_flows),
                'timing_analysis': self._perform_timing_analysis(encrypted_flows),
                'size_analysis': self._analyze_packet_sizes(encrypted_flows),
                'protocol_analysis': self._analyze_protocols(encrypted_flows),
                'fingerprinting': self._perform_encrypted_fingerprinting(encrypted_flows),
                'side_channel_analysis': self._side_channel_analysis(encrypted_flows),
                'website_fingerprinting': self._website_fingerprinting(encrypted_flows),
                'traffic_classification': self._classify_encrypted_traffic(encrypted_flows)
            }
            
            return results
            
        except Exception as e:
            return {'error': f"Encrypted traffic analysis failed: {str(e)}"}
    
    def analyze_encrypted_traffic(self, pcap_file: str) -> Dict:
        """Main analysis function called by GUI (duplicate method name fix)"""
        try:
            packets = rdpcap(pcap_file)
            
            # Extract encrypted flows
            encrypted_flows = self._identify_encrypted_flows(packets)
            
            # Perform various analyses
            results = {
                'encrypted_flows': encrypted_flows,
                'metadata_analysis': self._analyze_metadata(encrypted_flows),
                'traffic_patterns': self._analyze_traffic_patterns(encrypted_flows),
                'timing_analysis': self._perform_timing_analysis(encrypted_flows),
                'size_analysis': self._analyze_packet_sizes(encrypted_flows),
                'protocol_analysis': self._analyze_protocols(encrypted_flows),
                'fingerprinting': self._perform_encrypted_fingerprinting(encrypted_flows),
                'website_fingerprinting': self._website_fingerprinting(encrypted_flows),
                'application_classification': self._classify_encrypted_traffic(encrypted_flows),
                'side_channel_analysis': self._side_channel_analysis(encrypted_flows),
                'analyzed_ips': list(encrypted_flows.keys()) if encrypted_flows else []
            }
            
            return results
            
        except Exception as e:
            return {'error': f"Encrypted traffic analysis failed: {str(e)}"}
    
    def _identify_encrypted_flows(self, packets) -> Dict:
        """Identify encrypted traffic flows"""
        flows = defaultdict(lambda: {
            'packets': [],
            'timestamps': [],
            'sizes': [],
            'directions': [],
            'total_bytes': 0,
            'is_encrypted': False,
            'encryption_type': 'unknown',
            'flow_start': None,
            'flow_end': None
        })
        
        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                timestamp = float(pkt.time)
                
                if TCP in pkt:
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    protocol = 'TCP'
                elif UDP in pkt:
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                    protocol = 'UDP'
                else:
                    continue
                
                # Create flow identifier
                flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}_{protocol}"
                
                # Check if this is encrypted traffic
                is_encrypted, enc_type = self._detect_encryption(pkt, src_port, dst_port)
                
                # Store flow data
                flow_data = flows[flow_id]
                flow_data['packets'].append(pkt)
                flow_data['timestamps'].append(timestamp)
                flow_data['sizes'].append(len(pkt))
                flow_data['total_bytes'] += len(pkt)
                flow_data['is_encrypted'] = is_encrypted
                flow_data['encryption_type'] = enc_type
                
                if flow_data['flow_start'] is None:
                    flow_data['flow_start'] = timestamp
                flow_data['flow_end'] = timestamp
        
        # Filter only encrypted flows
        encrypted_flows = {k: v for k, v in flows.items() if v['is_encrypted']}
        return dict(encrypted_flows)
    
    def _detect_encryption(self, pkt, src_port: int, dst_port: int) -> Tuple[bool, str]:
        """Detect if packet contains encrypted data"""
        # Check for known VPN ports
        for port in [src_port, dst_port]:
            if port in self.vpn_ports:
                return True, self.vpn_ports[port]
        
        # Check for TLS/SSL traffic
        if dst_port == 443 or src_port == 443:
            return True, 'TLS/SSL'
        
        # Check for encrypted payload patterns
        if Raw in pkt:
            payload = pkt[Raw].load
            if self._is_encrypted_payload(payload):
                return True, 'Encrypted Payload'
        
        return False, 'Unencrypted'
    
    def _is_encrypted_payload(self, payload: bytes) -> bool:
        """Heuristic to detect encrypted payload"""
        if len(payload) < 20:
            return False
        
        # Calculate entropy
        entropy = self._calculate_entropy(payload)
        
        # High entropy suggests encryption
        return entropy > 7.5  # Threshold for encrypted data
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = Counter(data)
        data_len = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _analyze_metadata(self, encrypted_flows: Dict) -> Dict:
        """Analyze metadata of encrypted flows"""
        metadata = {
            'total_flows': len(encrypted_flows),
            'encryption_types': Counter(),
            'flow_durations': [],
            'total_encrypted_bytes': 0,
            'average_flow_size': 0,
            'flow_statistics': {}
        }
        
        for flow_id, flow_data in encrypted_flows.items():
            # Collect encryption types
            metadata['encryption_types'][flow_data['encryption_type']] += 1
            
            # Calculate flow duration
            if flow_data['flow_start'] and flow_data['flow_end']:
                duration = flow_data['flow_end'] - flow_data['flow_start']
                metadata['flow_durations'].append(duration)
            
            # Sum encrypted bytes
            metadata['total_encrypted_bytes'] += flow_data['total_bytes']
        
        # Calculate statistics
        if metadata['flow_durations']:
            metadata['average_flow_duration'] = statistics.mean(metadata['flow_durations'])
            metadata['median_flow_duration'] = statistics.median(metadata['flow_durations'])
        
        if metadata['total_flows'] > 0:
            metadata['average_flow_size'] = metadata['total_encrypted_bytes'] / metadata['total_flows']
        
        return metadata
    
    def _analyze_traffic_patterns(self, encrypted_flows: Dict) -> Dict:
        """Analyze traffic patterns in encrypted flows"""
        patterns = {
            'burst_patterns': {},
            'periodicity': {},
            'flow_relationships': [],
            'communication_patterns': {}
        }
        
        for flow_id, flow_data in encrypted_flows.items():
            timestamps = flow_data['timestamps']
            sizes = flow_data['sizes']
            
            if len(timestamps) > 1:
                # Analyze burst patterns
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                patterns['burst_patterns'][flow_id] = self._detect_bursts(intervals)
                
                # Analyze periodicity
                patterns['periodicity'][flow_id] = self._detect_periodicity(intervals)
        
        return patterns
    
    def _perform_timing_analysis(self, encrypted_flows: Dict) -> Dict:
        """Perform timing analysis on encrypted flows"""
        timing_analysis = {}
        
        for flow_id, flow_data in encrypted_flows.items():
            timestamps = flow_data['timestamps']
            
            if len(timestamps) > 2:
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                
                timing_signature = {
                    'mean_interval': statistics.mean(intervals),
                    'std_deviation': statistics.stdev(intervals) if len(intervals) > 1 else 0,
                    'min_interval': min(intervals),
                    'max_interval': max(intervals),
                    'interval_entropy': self._calculate_timing_entropy(intervals),
                    'timing_fingerprint': self._generate_timing_fingerprint(intervals)
                }
                
                timing_analysis[flow_id] = timing_signature
        
        return timing_analysis
    
    def _analyze_packet_sizes(self, encrypted_flows: Dict) -> Dict:
        """Analyze packet size patterns in encrypted traffic"""
        size_analysis = {}
        
        for flow_id, flow_data in encrypted_flows.items():
            sizes = flow_data['sizes']
            
            if sizes:
                size_signature = {
                    'mean_size': statistics.mean(sizes),
                    'median_size': statistics.median(sizes),
                    'size_variance': statistics.variance(sizes) if len(sizes) > 1 else 0,
                    'size_distribution': self._analyze_size_distribution(sizes),
                    'size_entropy': self._calculate_size_entropy(sizes),
                    'mtu_patterns': self._detect_mtu_patterns(sizes),
                    'padding_detection': self._detect_padding_patterns(sizes)
                }
                
                size_analysis[flow_id] = size_signature
        
        return size_analysis
    
    def _analyze_protocols(self, encrypted_flows: Dict) -> Dict:
        """Analyze protocol usage in encrypted traffic"""
        protocol_analysis = {
            'protocol_distribution': Counter(),
            'port_usage': Counter(),
            'protocol_sequences': {}
        }
        
        for flow_id, flow_data in encrypted_flows.items():
            # Extract protocol from flow_id
            if 'TCP' in flow_id:
                protocol_analysis['protocol_distribution']['TCP'] += 1
            elif 'UDP' in flow_id:
                protocol_analysis['protocol_distribution']['UDP'] += 1
            
            # Extract port information
            parts = flow_id.split('->')
            if len(parts) == 2:
                dst_part = parts[1].split('_')[0]
                if ':' in dst_part:
                    port = int(dst_part.split(':')[1])
                    protocol_analysis['port_usage'][port] += 1
        
        return protocol_analysis
    
    def _perform_encrypted_fingerprinting(self, encrypted_flows: Dict) -> Dict:
        """Create fingerprints of encrypted traffic"""
        fingerprints = {}
        
        for flow_id, flow_data in encrypted_flows.items():
            # Create comprehensive fingerprint
            fingerprint_data = {
                'size_pattern': self._create_size_pattern(flow_data['sizes']),
                'timing_pattern': self._create_timing_pattern(flow_data['timestamps']),
                'flow_characteristics': {
                    'packet_count': len(flow_data['packets']),
                    'total_bytes': flow_data['total_bytes'],
                    'encryption_type': flow_data['encryption_type']
                }
            }
            
            # Generate unique fingerprint hash
            fingerprint_string = str(fingerprint_data)
            fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]
            
            fingerprints[flow_id] = {
                'fingerprint_hash': fingerprint_hash,
                'characteristics': fingerprint_data
            }
        
        return fingerprints
    
    def _side_channel_analysis(self, encrypted_flows: Dict) -> Dict:
        """Perform side-channel analysis on encrypted traffic"""
        side_channel = {
            'traffic_volume_analysis': {},
            'inter_packet_timing': {},
            'packet_size_leakage': {},
            'flow_correlation': {}
        }
        
        # Traffic volume analysis
        for flow_id, flow_data in encrypted_flows.items():
            timestamps = flow_data['timestamps']
            sizes = flow_data['sizes']
            
            if len(timestamps) > 10:  # Need sufficient data
                # Volume over time analysis
                time_windows = self._create_time_windows(timestamps, sizes, window_size=1.0)
                side_channel['traffic_volume_analysis'][flow_id] = time_windows
                
                # Inter-packet timing patterns
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                side_channel['inter_packet_timing'][flow_id] = {
                    'timing_clusters': self._cluster_timing_intervals(intervals),
                    'timing_signature': self._generate_timing_signature(intervals)
                }
                
                # Packet size information leakage
                side_channel['packet_size_leakage'][flow_id] = {
                    'size_clusters': self._cluster_packet_sizes(sizes),
                    'size_patterns': self._identify_size_patterns(sizes)
                }
        
        return side_channel
    
    def _website_fingerprinting(self, encrypted_flows: Dict) -> Dict:
        """Attempt website fingerprinting on encrypted HTTPS traffic"""
        fingerprinting = {
            'potential_websites': {},
            'traffic_signatures': {},
            'page_load_patterns': {}
        }
        
        for flow_id, flow_data in encrypted_flows.items():
            if flow_data['encryption_type'] in ['TLS/SSL', 'SSL VPN']:
                # Analyze patterns that might indicate specific websites
                sizes = flow_data['sizes']
                timestamps = flow_data['timestamps']
                
                if len(sizes) > 5:
                    # Create traffic signature
                    signature = self._create_website_signature(sizes, timestamps)
                    fingerprinting['traffic_signatures'][flow_id] = signature
                    
                    # Look for page load patterns
                    page_pattern = self._detect_page_load_pattern(sizes, timestamps)
                    fingerprinting['page_load_patterns'][flow_id] = page_pattern
        
        return fingerprinting
    
    def _classify_encrypted_traffic(self, encrypted_flows: Dict) -> Dict:
        """Classify encrypted traffic by application type"""
        classification = {
            'web_browsing': [],
            'video_streaming': [],
            'file_transfer': [],
            'messaging': [],
            'vpn_tunnel': [],
            'unknown': []
        }
        
        for flow_id, flow_data in encrypted_flows.items():
            sizes = flow_data['sizes']
            timestamps = flow_data['timestamps']
            total_bytes = flow_data['total_bytes']
            
            # Classification heuristics
            if self._is_web_browsing(sizes, timestamps):
                classification['web_browsing'].append(flow_id)
            elif self._is_video_streaming(sizes, total_bytes):
                classification['video_streaming'].append(flow_id)
            elif self._is_file_transfer(sizes, total_bytes):
                classification['file_transfer'].append(flow_id)
            elif self._is_messaging(sizes, timestamps):
                classification['messaging'].append(flow_id)
            elif flow_data['encryption_type'] in self.vpn_ports.values():
                classification['vpn_tunnel'].append(flow_id)
            else:
                classification['unknown'].append(flow_id)
        
        return classification
    
    # Helper methods for analysis
    def _detect_bursts(self, intervals: List[float]) -> Dict:
        """Detect burst patterns in timing intervals"""
        if len(intervals) < 10:
            return {'bursts': 0}
        
        burst_threshold = statistics.mean(intervals) * 0.1  # 10% of mean
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
            'burst_count': bursts,
            'burst_ratio': bursts / len(intervals)
        }
    
    def _detect_periodicity(self, intervals: List[float]) -> Dict:
        """Detect periodic patterns in intervals"""
        if len(intervals) < 20:
            return {'periodic': False}
        
        # Simple periodicity detection using FFT
        try:
            fft_result = np.fft.fft(intervals[:100])
            power_spectrum = np.abs(fft_result) ** 2
            dominant_freq = np.argmax(power_spectrum[1:]) + 1
            
            return {
                'periodic': True,
                'dominant_frequency': dominant_freq,
                'periodicity_strength': float(np.max(power_spectrum[1:]) / np.sum(power_spectrum[1:]))
            }
        except:
            return {'periodic': False}
    
    def _calculate_timing_entropy(self, intervals: List[float]) -> float:
        """Calculate entropy of timing intervals"""
        if not intervals:
            return 0.0
        
        # Discretize intervals
        bins = np.histogram(intervals, bins=20)[0]
        bins = bins[bins > 0]
        
        if len(bins) == 0:
            return 0.0
        
        probabilities = bins / np.sum(bins)
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy
    
    def _generate_timing_fingerprint(self, intervals: List[float]) -> str:
        """Generate timing-based fingerprint"""
        if not intervals:
            return "NO_TIMING"
        
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        fingerprint_data = f"{mean_interval:.6f}_{std_interval:.6f}_{len(intervals)}"
        return hashlib.md5(fingerprint_data.encode()).hexdigest()[:12]
    
    def _analyze_size_distribution(self, sizes: List[int]) -> Dict:
        """Analyze distribution of packet sizes"""
        if not sizes:
            return {}
        
        return {
            'small_packets': len([s for s in sizes if s <= 100]),
            'medium_packets': len([s for s in sizes if 100 < s <= 1000]),
            'large_packets': len([s for s in sizes if s > 1000]),
            'mtu_sized': len([s for s in sizes if 1400 <= s <= 1500])
        }
    
    def _calculate_size_entropy(self, sizes: List[int]) -> float:
        """Calculate entropy of packet sizes"""
        if not sizes:
            return 0.0
        
        unique_sizes, counts = np.unique(sizes, return_counts=True)
        probabilities = counts / np.sum(counts)
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy
    
    def _detect_mtu_patterns(self, sizes: List[int]) -> Dict:
        """Detect MTU-related patterns"""
        if not sizes:
            return {}
        
        mtu_1500 = len([s for s in sizes if 1450 <= s <= 1500])
        mtu_1492 = len([s for s in sizes if 1442 <= s <= 1492])
        
        return {
            'mtu_1500_packets': mtu_1500,
            'mtu_1492_packets': mtu_1492,
            'fragmented_likely': len([s for s in sizes if s > 1500])
        }
    
    def _detect_padding_patterns(self, sizes: List[int]) -> Dict:
        """Detect traffic padding patterns"""
        if not sizes:
            return {}
        
        # Common padding sizes
        padding_sizes = [64, 128, 256, 512, 1024]
        padding_detected = {}
        
        for pad_size in padding_sizes:
            count = len([s for s in sizes if abs(s - pad_size) <= 10])
            padding_detected[f'padding_{pad_size}'] = count
        
        return padding_detected
    
    def _create_size_pattern(self, sizes: List[int]) -> str:
        """Create size-based pattern signature"""
        if not sizes:
            return "NO_SIZES"
        
        # Create histogram and convert to signature
        hist, _ = np.histogram(sizes, bins=10)
        pattern = ''.join([str(int(h/max(hist)*9)) for h in hist])
        return pattern
    
    def _create_timing_pattern(self, timestamps: List[float]) -> str:
        """Create timing-based pattern signature"""
        if len(timestamps) < 2:
            return "NO_TIMING"
        
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        # Discretize intervals and create pattern
        hist, _ = np.histogram(intervals, bins=10)
        pattern = ''.join([str(int(h/max(hist)*9)) if max(hist) > 0 else '0' for h in hist])
        return pattern
    
    def _create_time_windows(self, timestamps: List[float], sizes: List[int], window_size: float = 1.0) -> List[Dict]:
        """Create time windows for volume analysis"""
        if not timestamps:
            return []
        
        start_time = min(timestamps)
        end_time = max(timestamps)
        windows = []
        
        current_time = start_time
        while current_time < end_time:
            window_end = current_time + window_size
            
            # Count packets and bytes in this window
            window_packets = 0
            window_bytes = 0
            
            for i, ts in enumerate(timestamps):
                if current_time <= ts < window_end:
                    window_packets += 1
                    window_bytes += sizes[i]
            
            windows.append({
                'start_time': current_time,
                'end_time': window_end,
                'packet_count': window_packets,
                'byte_count': window_bytes
            })
            
            current_time = window_end
        
        return windows
    
    def _cluster_timing_intervals(self, intervals: List[float]) -> Dict:
        """Cluster timing intervals to find patterns"""
        if len(intervals) < 10:
            return {'clusters': 0}
        
        # Simple clustering based on interval ranges
        fast = len([i for i in intervals if i < 0.01])  # < 10ms
        medium = len([i for i in intervals if 0.01 <= i < 0.1])  # 10-100ms
        slow = len([i for i in intervals if i >= 0.1])  # > 100ms
        
        return {
            'fast_intervals': fast,
            'medium_intervals': medium,
            'slow_intervals': slow,
            'dominant_cluster': 'fast' if fast > max(medium, slow) else 'medium' if medium > slow else 'slow'
        }
    
    def _generate_timing_signature(self, intervals: List[float]) -> str:
        """Generate timing signature for correlation"""
        if not intervals:
            return "NO_TIMING"
        
        # Create signature from timing characteristics
        mean_time = statistics.mean(intervals)
        std_time = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        signature_data = f"{mean_time:.6f}_{std_time:.6f}"
        return hashlib.sha256(signature_data.encode()).hexdigest()[:16]
    
    def _cluster_packet_sizes(self, sizes: List[int]) -> Dict:
        """Cluster packet sizes to identify patterns"""
        if not sizes:
            return {}
        
        small = len([s for s in sizes if s <= 100])
        medium = len([s for s in sizes if 100 < s <= 1000])
        large = len([s for s in sizes if s > 1000])
        
        return {
            'small_packets': small,
            'medium_packets': medium,
            'large_packets': large,
            'size_diversity': len(set(sizes))
        }
    
    def _identify_size_patterns(self, sizes: List[int]) -> Dict:
        """Identify specific size patterns"""
        if not sizes:
            return {}
        
        # Look for common application patterns
        patterns = {
            'web_request_pattern': len([s for s in sizes if 200 <= s <= 800]),
            'web_response_pattern': len([s for s in sizes if 1000 <= s <= 1500]),
            'keep_alive_pattern': len([s for s in sizes if s <= 100]),
            'data_transfer_pattern': len([s for s in sizes if s > 1400])
        }
        
        return patterns
    
    def _create_website_signature(self, sizes: List[int], timestamps: List[float]) -> Dict:
        """Create signature for potential website identification"""
        if len(sizes) < 5:
            return {}
        
        # Analyze first few packets (typical of web page loads)
        initial_sizes = sizes[:10]
        
        signature = {
            'initial_request_size': sizes[0] if sizes else 0,
            'response_pattern': initial_sizes[1:6] if len(initial_sizes) > 5 else [],
            'total_initial_bytes': sum(initial_sizes),
            'request_response_ratio': self._calculate_request_response_ratio(sizes)
        }
        
        return signature
    
    def _detect_page_load_pattern(self, sizes: List[int], timestamps: List[float]) -> Dict:
        """Detect patterns typical of web page loading"""
        if len(sizes) < 10:
            return {'page_load_detected': False}
        
        # Look for initial burst followed by resource loading
        initial_burst = len([s for i, s in enumerate(sizes[:5]) if s > 1000])
        resource_requests = len([s for s in sizes[5:] if 100 <= s <= 800])
        
        return {
            'page_load_detected': initial_burst >= 2 and resource_requests >= 3,
            'initial_burst_size': initial_burst,
            'resource_requests': resource_requests
        }
    
    def _calculate_request_response_ratio(self, sizes: List[int]) -> float:
        """Calculate ratio of small (request) to large (response) packets"""
        if not sizes:
            return 0.0
        
        requests = len([s for s in sizes if s <= 500])
        responses = len([s for s in sizes if s > 500])
        
        return requests / responses if responses > 0 else float('inf')
    
    # Traffic classification methods
    def _is_web_browsing(self, sizes: List[int], timestamps: List[float]) -> bool:
        """Detect web browsing patterns"""
        if len(sizes) < 5:
            return False
        
        # Web browsing typically has mixed small/large packets
        small_packets = len([s for s in sizes if s <= 500])
        large_packets = len([s for s in sizes if s > 1000])
        
        return small_packets > 0 and large_packets > 0 and small_packets / len(sizes) > 0.3
    
    def _is_video_streaming(self, sizes: List[int], total_bytes: int) -> bool:
        """Detect video streaming patterns"""
        if not sizes:
            return False
        
        # Video streaming typically has consistent large packets
        large_packets = len([s for s in sizes if s > 1200])
        avg_size = statistics.mean(sizes)
        
        return large_packets / len(sizes) > 0.7 and avg_size > 1000 and total_bytes > 1000000
    
    def _is_file_transfer(self, sizes: List[int], total_bytes: int) -> bool:
        """Detect file transfer patterns"""
        if not sizes:
            return False
        
        # File transfer typically has very consistent large packets
        large_packets = len([s for s in sizes if s > 1400])
        size_consistency = statistics.stdev(sizes) / statistics.mean(sizes) if len(sizes) > 1 and statistics.mean(sizes) > 0 else 0
        
        return large_packets / len(sizes) > 0.8 and size_consistency < 0.2 and total_bytes > 100000
    
    def _is_messaging(self, sizes: List[int], timestamps: List[float]) -> bool:
        """Detect messaging patterns"""
        if len(sizes) < 3:
            return False
        
        # Messaging typically has small, irregular packets
        small_packets = len([s for s in sizes if s <= 200])
        
        if len(timestamps) > 1:
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            irregular_timing = statistics.stdev(intervals) > statistics.mean(intervals) * 0.5 if len(intervals) > 1 else False
            return small_packets / len(sizes) > 0.8 and irregular_timing
        
        return small_packets / len(sizes) > 0.8

def analyze_encrypted_traffic(pcap_file: str) -> Dict:
    """Main function to analyze encrypted VPN traffic"""
    analyzer = EncryptedTrafficAnalyzer()
    return analyzer.analyze_encrypted_traffic(pcap_file)
