#!/usr/bin/env python3
"""
Traffic Correlation Analysis Module
Implements traffic flow correlation techniques for network de-anonymization.
WARNING: Use only for authorized network analysis and research purposes.
"""

import numpy as np
import statistics
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional
from scapy.all import rdpcap, IP, TCP, UDP
import hashlib
import time

class TrafficCorrelationAnalyzer:
    """Advanced traffic correlation analysis for flow matching and de-anonymization"""
    
    def __init__(self, correlation_window: float = 60.0):
        self.correlation_window = correlation_window  # Time window in seconds
        self.flow_patterns = {}
        self.timing_signatures = {}
        
    def analyze_traffic_flows(self, pcap_file: str) -> Dict:
        """Analyze traffic flows for correlation patterns"""
        try:
            packets = rdpcap(pcap_file)
            
            # Extract flows and timing patterns
            flows = self._extract_flows(packets)
            timing_patterns = self._analyze_timing_patterns(flows)
            size_patterns = self._analyze_size_patterns(flows)
            correlation_matrix = self._build_correlation_matrix(flows)
            
            results = {
                'flows': flows,
                'timing_patterns': timing_patterns,
                'size_patterns': size_patterns,
                'correlation_matrix': correlation_matrix,
                'potential_matches': self._find_potential_matches(flows),
                'anonymization_detection': self._detect_anonymization_techniques(flows)
            }
            
            return results
            
        except Exception as e:
            return {'error': f"Traffic correlation analysis failed: {str(e)}"}
    
    def analyze_traffic_correlation(self, pcap_file: str) -> Dict:
        """Main analysis function called by GUI"""
        return self.analyze_traffic_flows(pcap_file)
    
    def _extract_flows(self, packets) -> Dict:
        """Extract network flows from packet capture"""
        flows = defaultdict(lambda: {
            'packets': [],
            'timestamps': [],
            'sizes': [],
            'directions': [],
            'total_bytes': 0,
            'duration': 0,
            'packet_count': 0
        })
        
        for pkt in packets:
            if IP in pkt:
                # Create flow identifier
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                
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
                
                # Normalize flow (smaller IP first for bidirectional flows)
                if src_ip < dst_ip:
                    flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}_{protocol}"
                    direction = 'forward'
                else:
                    flow_id = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}_{protocol}"
                    direction = 'reverse'
                
                # Store flow data
                flows[flow_id]['packets'].append(pkt)
                flows[flow_id]['timestamps'].append(float(pkt.time))
                flows[flow_id]['sizes'].append(len(pkt))
                flows[flow_id]['directions'].append(direction)
                flows[flow_id]['total_bytes'] += len(pkt)
                flows[flow_id]['packet_count'] += 1
        
        # Calculate flow durations
        for flow_id, flow_data in flows.items():
            if flow_data['timestamps']:
                flow_data['duration'] = max(flow_data['timestamps']) - min(flow_data['timestamps'])
        
        return dict(flows)
    
    def _analyze_timing_patterns(self, flows: Dict) -> Dict:
        """Analyze timing patterns in network flows"""
        timing_analysis = {}
        
        for flow_id, flow_data in flows.items():
            timestamps = flow_data['timestamps']
            if len(timestamps) < 2:
                continue
            
            # Calculate inter-packet intervals
            intervals = []
            for i in range(1, len(timestamps)):
                intervals.append(timestamps[i] - timestamps[i-1])
            
            # Timing pattern analysis
            timing_signature = {
                'mean_interval': statistics.mean(intervals),
                'median_interval': statistics.median(intervals),
                'std_deviation': statistics.stdev(intervals) if len(intervals) > 1 else 0,
                'min_interval': min(intervals),
                'max_interval': max(intervals),
                'interval_distribution': self._calculate_interval_distribution(intervals),
                'burst_patterns': self._detect_burst_patterns(intervals),
                'periodicity_score': self._calculate_periodicity_score(intervals),
                'timing_entropy': self._calculate_timing_entropy(intervals)
            }
            
            timing_analysis[flow_id] = timing_signature
        
        return timing_analysis
    
    def _analyze_size_patterns(self, flows: Dict) -> Dict:
        """Analyze packet size patterns in flows"""
        size_analysis = {}
        
        for flow_id, flow_data in flows.items():
            sizes = flow_data['sizes']
            if not sizes:
                continue
            
            size_signature = {
                'mean_size': statistics.mean(sizes),
                'median_size': statistics.median(sizes),
                'size_variance': statistics.variance(sizes) if len(sizes) > 1 else 0,
                'size_distribution': self._calculate_size_distribution(sizes),
                'mtu_patterns': self._detect_mtu_patterns(sizes),
                'size_entropy': self._calculate_size_entropy(sizes),
                'fragmentation_indicators': self._detect_fragmentation(sizes)
            }
            
            size_analysis[flow_id] = size_signature
        
        return size_analysis
    
    def _build_correlation_matrix(self, flows: Dict) -> Dict:
        """Build correlation matrix between flows"""
        flow_ids = list(flows.keys())
        correlation_matrix = {}
        
        for i, flow1_id in enumerate(flow_ids):
            correlation_matrix[flow1_id] = {}
            for j, flow2_id in enumerate(flow_ids):
                if i != j:
                    correlation_score = self._calculate_flow_correlation(
                        flows[flow1_id], flows[flow2_id]
                    )
                    correlation_matrix[flow1_id][flow2_id] = correlation_score
        
        return correlation_matrix
    
    def _calculate_flow_correlation(self, flow1: Dict, flow2: Dict) -> float:
        """Calculate correlation score between two flows"""
        # Time-based correlation
        time_correlation = self._calculate_time_correlation(
            flow1['timestamps'], flow2['timestamps']
        )
        
        # Size-based correlation
        size_correlation = self._calculate_size_correlation(
            flow1['sizes'], flow2['sizes']
        )
        
        # Pattern-based correlation
        pattern_correlation = self._calculate_pattern_correlation(flow1, flow2)
        
        # Combined correlation score
        total_correlation = (time_correlation * 0.4 + 
                           size_correlation * 0.3 + 
                           pattern_correlation * 0.3)
        
        return total_correlation
    
    def _calculate_time_correlation(self, timestamps1: List[float], timestamps2: List[float]) -> float:
        """Calculate temporal correlation between two flows"""
        if not timestamps1 or not timestamps2:
            return 0.0
        
        # Normalize timestamps to start from 0
        norm_ts1 = [t - min(timestamps1) for t in timestamps1]
        norm_ts2 = [t - min(timestamps2) for t in timestamps2]
        
        # Calculate cross-correlation using sliding window
        max_correlation = 0.0
        window_size = min(len(norm_ts1), len(norm_ts2), 50)  # Limit window size
        
        for offset in range(-window_size, window_size):
            correlation = self._calculate_windowed_correlation(norm_ts1, norm_ts2, offset)
            max_correlation = max(max_correlation, correlation)
        
        return max_correlation
    
    def _calculate_windowed_correlation(self, ts1: List[float], ts2: List[float], offset: int) -> float:
        """Calculate correlation with time offset"""
        if offset >= 0:
            aligned_ts1 = ts1[offset:]
            aligned_ts2 = ts2[:len(aligned_ts1)]
        else:
            aligned_ts1 = ts1[:len(ts1) + offset]
            aligned_ts2 = ts2[-offset:len(aligned_ts1) - offset]
        
        if len(aligned_ts1) < 2 or len(aligned_ts2) < 2:
            return 0.0
        
        # Calculate correlation coefficient with safety checks
        try:
            if len(aligned_ts1) < 2 or len(aligned_ts2) < 2:
                return 0.0
            
            arr1 = np.array(aligned_ts1)
            arr2 = np.array(aligned_ts2)
            
            # Check for zero variance
            if np.std(arr1) == 0 or np.std(arr2) == 0:
                return 1.0 if np.array_equal(arr1, arr2) else 0.0
            
            correlation = np.corrcoef(arr1, arr2)[0, 1]
            return abs(correlation) if not np.isnan(correlation) else 0.0
        except:
            return 0.0
    
    def _calculate_size_correlation(self, sizes1: List[int], sizes2: List[int]) -> float:
        """Calculate size pattern correlation"""
        if not sizes1 or not sizes2:
            return 0.0
        
        # Compare size distributions
        hist1 = self._create_size_histogram(sizes1)
        hist2 = self._create_size_histogram(sizes2)
        
        # Calculate histogram correlation
        correlation = self._calculate_histogram_correlation(hist1, hist2)
        return correlation
    
    def _calculate_pattern_correlation(self, flow1: Dict, flow2: Dict) -> float:
        """Calculate pattern-based correlation"""
        # Compare packet count patterns
        count_similarity = 1.0 - abs(flow1['packet_count'] - flow2['packet_count']) / max(flow1['packet_count'], flow2['packet_count'])
        
        # Compare duration patterns
        duration_similarity = 1.0 - abs(flow1['duration'] - flow2['duration']) / max(flow1['duration'], flow2['duration'], 1.0)
        
        # Compare byte patterns
        byte_similarity = 1.0 - abs(flow1['total_bytes'] - flow2['total_bytes']) / max(flow1['total_bytes'], flow2['total_bytes'])
        
        return (count_similarity + duration_similarity + byte_similarity) / 3.0
    
    def _find_potential_matches(self, flows: Dict) -> List[Dict]:
        """Find potentially correlated flows that might indicate tunneling/anonymization"""
        potential_matches = []
        
        flow_list = list(flows.items())
        for i in range(len(flow_list)):
            for j in range(i + 1, len(flow_list)):
                flow1_id, flow1_data = flow_list[i]
                flow2_id, flow2_data = flow_list[j]
                
                # Calculate various correlation metrics
                time_overlap = self._calculate_time_overlap(flow1_data, flow2_data)
                size_similarity = self._calculate_size_similarity(flow1_data, flow2_data)
                timing_similarity = self._calculate_timing_similarity(flow1_data, flow2_data)
                
                # Combined match score
                match_score = (time_overlap * 0.4 + size_similarity * 0.3 + timing_similarity * 0.3)
                
                if match_score > 0.7:  # High correlation threshold
                    potential_matches.append({
                        'flow1': flow1_id,
                        'flow2': flow2_id,
                        'match_score': match_score,
                        'time_overlap': time_overlap,
                        'size_similarity': size_similarity,
                        'timing_similarity': timing_similarity,
                        'analysis': self._analyze_flow_relationship(flow1_data, flow2_data)
                    })
        
        # Sort by match score
        potential_matches.sort(key=lambda x: x['match_score'], reverse=True)
        return potential_matches
    
    def _detect_anonymization_techniques(self, flows: Dict) -> Dict:
        """Detect potential anonymization techniques in traffic"""
        detection_results = {
            'tor_indicators': [],
            'vpn_indicators': [],
            'proxy_indicators': [],
            'traffic_shaping': [],
            'padding_detection': [],
            'timing_obfuscation': []
        }
        
        for flow_id, flow_data in flows.items():
            # Tor detection (multiple hops, specific timing patterns)
            if self._detect_tor_patterns(flow_data):
                detection_results['tor_indicators'].append(flow_id)
            
            # VPN detection (encrypted tunnels, specific ports)
            if self._detect_vpn_patterns(flow_data):
                detection_results['vpn_indicators'].append(flow_id)
            
            # Proxy detection (HTTP CONNECT, specific patterns)
            if self._detect_proxy_patterns(flow_data):
                detection_results['proxy_indicators'].append(flow_id)
            
            # Traffic shaping detection
            if self._detect_traffic_shaping(flow_data):
                detection_results['traffic_shaping'].append(flow_id)
            
            # Padding detection
            if self._detect_padding(flow_data):
                detection_results['padding_detection'].append(flow_id)
            
            # Timing obfuscation detection
            if self._detect_timing_obfuscation(flow_data):
                detection_results['timing_obfuscation'].append(flow_id)
        
        return detection_results
    
    def _calculate_interval_distribution(self, intervals: List[float]) -> Dict:
        """Calculate distribution of inter-packet intervals"""
        if not intervals:
            return {}
        
        # Categorize intervals
        categories = {
            'very_short': len([i for i in intervals if i < 0.001]),  # < 1ms
            'short': len([i for i in intervals if 0.001 <= i < 0.01]),  # 1-10ms
            'medium': len([i for i in intervals if 0.01 <= i < 0.1]),  # 10-100ms
            'long': len([i for i in intervals if 0.1 <= i < 1.0]),  # 100ms-1s
            'very_long': len([i for i in intervals if i >= 1.0])  # > 1s
        }
        
        return categories
    
    def _detect_burst_patterns(self, intervals: List[float]) -> Dict:
        """Detect burst patterns in packet timing"""
        if len(intervals) < 10:
            return {'bursts': 0, 'burst_intensity': 0}
        
        burst_threshold = 0.01  # 10ms threshold
        bursts = []
        current_burst = []
        
        for interval in intervals:
            if interval < burst_threshold:
                current_burst.append(interval)
            else:
                if len(current_burst) > 2:  # Minimum burst size
                    bursts.append(current_burst)
                current_burst = []
        
        return {
            'bursts': len(bursts),
            'burst_intensity': sum(len(b) for b in bursts) / len(intervals),
            'avg_burst_size': statistics.mean([len(b) for b in bursts]) if bursts else 0
        }
    
    def _calculate_periodicity_score(self, intervals: List[float]) -> float:
        """Calculate periodicity score for timing patterns"""
        if len(intervals) < 20:
            return 0.0
        
        # Use FFT to detect periodic patterns
        try:
            # Resample intervals to fixed time grid
            fft_result = np.fft.fft(intervals[:100])  # Limit to first 100 intervals
            power_spectrum = np.abs(fft_result) ** 2
            
            # Find dominant frequency
            dominant_freq_power = np.max(power_spectrum[1:])  # Exclude DC component
            total_power = np.sum(power_spectrum[1:])
            
            periodicity_score = dominant_freq_power / total_power if total_power > 0 else 0
            return min(periodicity_score, 1.0)
        except:
            return 0.0
    
    def _calculate_timing_entropy(self, intervals: List[float]) -> float:
        """Calculate entropy of timing patterns"""
        if not intervals:
            return 0.0
        
        # Discretize intervals into bins
        bins = np.histogram(intervals, bins=20)[0]
        bins = bins[bins > 0]  # Remove empty bins
        
        if len(bins) == 0:
            return 0.0
        
        # Calculate entropy
        probabilities = bins / np.sum(bins)
        entropy = -np.sum(probabilities * np.log2(probabilities))
        
        return entropy
    
    def _calculate_size_distribution(self, sizes: List[int]) -> Dict:
        """Calculate packet size distribution"""
        if not sizes:
            return {}
        
        size_categories = {
            'tiny': len([s for s in sizes if s <= 64]),
            'small': len([s for s in sizes if 64 < s <= 256]),
            'medium': len([s for s in sizes if 256 < s <= 1024]),
            'large': len([s for s in sizes if 1024 < s <= 1500]),
            'jumbo': len([s for s in sizes if s > 1500])
        }
        
        return size_categories
    
    def _detect_mtu_patterns(self, sizes: List[int]) -> Dict:
        """Detect MTU and fragmentation patterns"""
        if not sizes:
            return {}
        
        # Common MTU sizes
        common_mtus = [1500, 1492, 1460, 576, 1280, 9000]
        
        mtu_analysis = {}
        for mtu in common_mtus:
            near_mtu = len([s for s in sizes if abs(s - mtu) <= 40])
            mtu_analysis[f'mtu_{mtu}'] = near_mtu
        
        return mtu_analysis
    
    def _calculate_size_entropy(self, sizes: List[int]) -> float:
        """Calculate entropy of packet sizes"""
        if not sizes:
            return 0.0
        
        # Create histogram of sizes
        unique_sizes, counts = np.unique(sizes, return_counts=True)
        probabilities = counts / np.sum(counts)
        
        # Calculate entropy
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy
    
    def _detect_fragmentation(self, sizes: List[int]) -> Dict:
        """Detect fragmentation patterns"""
        if not sizes:
            return {}
        
        # Look for fragmentation indicators
        max_size = max(sizes)
        fragmented_packets = len([s for s in sizes if s == max_size and s > 1400])
        
        return {
            'max_packet_size': max_size,
            'potential_fragments': fragmented_packets,
            'fragmentation_ratio': fragmented_packets / len(sizes)
        }
    
    def _create_size_histogram(self, sizes: List[int], bins: int = 20) -> np.ndarray:
        """Create histogram of packet sizes"""
        if not sizes:
            return np.array([])
        
        hist, _ = np.histogram(sizes, bins=bins)
        return hist
    
    def _calculate_histogram_correlation(self, hist1: np.ndarray, hist2: np.ndarray) -> float:
        """Calculate correlation between two histograms"""
        if len(hist1) == 0 or len(hist2) == 0:
            return 0.0
        
        # Normalize histograms
        norm_hist1 = hist1 / np.sum(hist1) if np.sum(hist1) > 0 else hist1
        norm_hist2 = hist2 / np.sum(hist2) if np.sum(hist2) > 0 else hist2
        
        # Calculate correlation with safety checks
        try:
            if len(norm_hist1) < 2 or len(norm_hist2) < 2:
                return 0.0
            
            arr1 = np.array(norm_hist1)
            arr2 = np.array(norm_hist2)
            
            # Check for zero variance
            if np.std(arr1) == 0 or np.std(arr2) == 0:
                return 1.0 if np.array_equal(arr1, arr2) else 0.0
            
            correlation = np.corrcoef(arr1, arr2)[0, 1]
            return abs(correlation) if not np.isnan(correlation) else 0.0
        except:
            return 0.0
    
    def _calculate_time_overlap(self, flow1: Dict, flow2: Dict) -> float:
        """Calculate temporal overlap between flows"""
        if not flow1['timestamps'] or not flow2['timestamps']:
            return 0.0
        
        start1, end1 = min(flow1['timestamps']), max(flow1['timestamps'])
        start2, end2 = min(flow2['timestamps']), max(flow2['timestamps'])
        
        overlap_start = max(start1, start2)
        overlap_end = min(end1, end2)
        
        if overlap_end <= overlap_start:
            return 0.0
        
        overlap_duration = overlap_end - overlap_start
        total_duration = max(end1, end2) - min(start1, start2)
        
        return overlap_duration / total_duration if total_duration > 0 else 0.0
    
    def _calculate_size_similarity(self, flow1: Dict, flow2: Dict) -> float:
        """Calculate size pattern similarity"""
        if not flow1['sizes'] or not flow2['sizes']:
            return 0.0
        
        mean1, mean2 = statistics.mean(flow1['sizes']), statistics.mean(flow2['sizes'])
        size_diff = abs(mean1 - mean2) / max(mean1, mean2)
        
        return 1.0 - size_diff
    
    def _calculate_timing_similarity(self, flow1: Dict, flow2: Dict) -> float:
        """Calculate timing pattern similarity"""
        if len(flow1['timestamps']) < 2 or len(flow2['timestamps']) < 2:
            return 0.0
        
        # Calculate inter-packet intervals
        intervals1 = [flow1['timestamps'][i+1] - flow1['timestamps'][i] 
                     for i in range(len(flow1['timestamps'])-1)]
        intervals2 = [flow2['timestamps'][i+1] - flow2['timestamps'][i] 
                     for i in range(len(flow2['timestamps'])-1)]
        
        if not intervals1 or not intervals2:
            return 0.0
        
        mean1, mean2 = statistics.mean(intervals1), statistics.mean(intervals2)
        timing_diff = abs(mean1 - mean2) / max(mean1, mean2)
        
        return 1.0 - timing_diff
    
    def _analyze_flow_relationship(self, flow1: Dict, flow2: Dict) -> Dict:
        """Analyze relationship between two flows"""
        analysis = {
            'temporal_relationship': 'overlapping' if self._calculate_time_overlap(flow1, flow2) > 0.5 else 'sequential',
            'size_relationship': 'similar' if self._calculate_size_similarity(flow1, flow2) > 0.8 else 'different',
            'potential_tunnel': self._detect_potential_tunnel(flow1, flow2),
            'correlation_strength': 'high' if self._calculate_flow_correlation(flow1, flow2) > 0.8 else 'medium'
        }
        
        return analysis
    
    def _detect_potential_tunnel(self, flow1: Dict, flow2: Dict) -> bool:
        """Detect if flows might represent a tunnel relationship"""
        # Simple heuristic: one flow contains the other in terms of bytes and timing
        bytes_ratio = min(flow1['total_bytes'], flow2['total_bytes']) / max(flow1['total_bytes'], flow2['total_bytes'])
        time_overlap = self._calculate_time_overlap(flow1, flow2)
        
        return bytes_ratio > 0.8 and time_overlap > 0.9
    
    def _detect_tor_patterns(self, flow_data: Dict) -> bool:
        """Detect Tor-like traffic patterns"""
        # Tor typically uses 512-byte cells, specific timing patterns
        sizes = flow_data['sizes']
        if not sizes:
            return False
        
        # Check for 512-byte cell patterns
        cell_size_count = len([s for s in sizes if abs(s - 512) <= 50])
        cell_ratio = cell_size_count / len(sizes)
        
        return cell_ratio > 0.3  # High proportion of cell-sized packets
    
    def _detect_vpn_patterns(self, flow_data: Dict) -> bool:
        """Detect VPN-like traffic patterns"""
        # VPN traffic often shows consistent encryption overhead
        sizes = flow_data['sizes']
        if not sizes:
            return False
        
        # Check for consistent size patterns (encryption overhead)
        size_variance = statistics.variance(sizes) if len(sizes) > 1 else 0
        mean_size = statistics.mean(sizes)
        
        # Low variance relative to mean suggests encryption padding
        coefficient_of_variation = (size_variance ** 0.5) / mean_size if mean_size > 0 else 0
        
        return coefficient_of_variation < 0.3  # Low variation suggests encryption
    
    def _detect_proxy_patterns(self, flow_data: Dict) -> bool:
        """Detect proxy-like traffic patterns"""
        # Proxy traffic often shows request-response patterns
        timestamps = flow_data['timestamps']
        if len(timestamps) < 4:
            return False
        
        # Look for alternating timing patterns
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        # Check for request-response timing patterns
        short_intervals = len([i for i in intervals if i < 0.1])
        return short_intervals / len(intervals) > 0.7  # High proportion of quick responses
    
    def _detect_traffic_shaping(self, flow_data: Dict) -> bool:
        """Detect traffic shaping patterns"""
        timestamps = flow_data['timestamps']
        if len(timestamps) < 10:
            return False
        
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        # Traffic shaping often creates very regular intervals
        std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        mean_interval = statistics.mean(intervals)
        
        coefficient_of_variation = std_dev / mean_interval if mean_interval > 0 else 0
        
        return coefficient_of_variation < 0.1  # Very regular timing
    
    def _detect_padding(self, flow_data: Dict) -> bool:
        """Detect traffic padding patterns"""
        sizes = flow_data['sizes']
        if not sizes:
            return False
        
        # Padding often creates packets of specific sizes
        common_sizes = [64, 128, 256, 512, 1024, 1500]
        padded_count = sum(len([s for s in sizes if abs(s - size) <= 10]) for size in common_sizes)
        
        return padded_count / len(sizes) > 0.8  # High proportion of standard sizes
    
    def _detect_timing_obfuscation(self, flow_data: Dict) -> bool:
        """Detect timing obfuscation patterns"""
        timestamps = flow_data['timestamps']
        if len(timestamps) < 20:
            return False
        
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        # Timing obfuscation often creates artificial randomness
        entropy = self._calculate_timing_entropy(intervals)
        
        return entropy > 4.0  # High entropy suggests artificial randomization

def analyze_traffic_correlation(pcap_file: str, correlation_window: float = 60.0) -> Dict:
    """Main function to perform traffic correlation analysis"""
    analyzer = TrafficCorrelationAnalyzer(correlation_window)
    return analyzer.analyze_traffic_flows(pcap_file)
