#!/usr/bin/env python3
"""
Traffic Flow Correlation Module
Advanced traffic flow analysis for VPN de-anonymization and correlation attacks
"""

import statistics
import numpy as np
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional
from scapy.all import rdpcap, IP, TCP, UDP, Raw
import time
import hashlib

class TrafficFlowCorrelator:
    """Advanced traffic flow correlation for de-anonymization"""
    
    def __init__(self):
        self.flows = {}
        self.correlation_matrix = {}
        self.timing_patterns = {}
        
    def analyze_traffic_flows(self, pcap_file: str) -> Dict:
        """Analyze traffic flows for correlation patterns"""
        try:
            packets = rdpcap(pcap_file)
            results = {
                'flow_analysis': {},
                'correlation_results': {},
                'timing_correlations': {},
                'pattern_matching': {},
                'flow_fingerprints': {}
            }
            
            # Extract and analyze flows
            flows = self._extract_flows(packets)
            results['flow_analysis'] = self._analyze_flows(flows)
            
            # Perform correlation analysis
            results['correlation_results'] = self._correlate_flows(flows)
            
            # Timing-based correlation
            results['timing_correlations'] = self._timing_correlation(flows)
            
            # Pattern matching
            results['pattern_matching'] = self._pattern_matching(flows)
            
            # Generate flow fingerprints
            results['flow_fingerprints'] = self._generate_flow_fingerprints(flows)
            
            return results
            
        except Exception as e:
            return {'error': f"Traffic flow correlation failed: {str(e)}"}
    
    def _extract_flows(self, packets) -> Dict:
        """Extract network flows from packets"""
        flows = defaultdict(lambda: {
            'packets': [],
            'sizes': [],
            'timestamps': [],
            'directions': [],
            'inter_arrival_times': [],
            'protocols': set(),
            'flags': []
        })
        
        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                
                # Create flow identifier
                if TCP in pkt:
                    flow_id = f"{src_ip}:{pkt[TCP].sport}-{dst_ip}:{pkt[TCP].dport}"
                    protocol = 'TCP'
                    flags = pkt[TCP].flags
                elif UDP in pkt:
                    flow_id = f"{src_ip}:{pkt[UDP].sport}-{dst_ip}:{pkt[UDP].dport}"
                    protocol = 'UDP'
                    flags = 0
                else:
                    flow_id = f"{src_ip}-{dst_ip}"
                    protocol = 'OTHER'
                    flags = 0
                
                # Store flow data
                flows[flow_id]['packets'].append(pkt)
                flows[flow_id]['sizes'].append(len(pkt))
                flows[flow_id]['timestamps'].append(float(pkt.time))
                flows[flow_id]['protocols'].add(protocol)
                flows[flow_id]['flags'].append(flags)
                
                # Determine direction (assuming first IP is client)
                if src_ip < dst_ip:
                    flows[flow_id]['directions'].append('outbound')
                else:
                    flows[flow_id]['directions'].append('inbound')
        
        # Calculate inter-arrival times
        for flow_id, flow_data in flows.items():
            timestamps = sorted(flow_data['timestamps'])
            for i in range(1, len(timestamps)):
                flow_data['inter_arrival_times'].append(timestamps[i] - timestamps[i-1])
        
        return dict(flows)
    
    def _analyze_flows(self, flows: Dict) -> Dict:
        """Analyze individual flows"""
        analysis = {
            'total_flows': len(flows),
            'flow_statistics': {},
            'flow_characteristics': {}
        }
        
        for flow_id, flow_data in flows.items():
            if not flow_data['packets']:
                continue
                
            # Basic statistics
            stats = {
                'packet_count': len(flow_data['packets']),
                'total_bytes': sum(flow_data['sizes']),
                'duration': max(flow_data['timestamps']) - min(flow_data['timestamps']) if len(flow_data['timestamps']) > 1 else 0,
                'avg_packet_size': statistics.mean(flow_data['sizes']) if flow_data['sizes'] else 0,
                'packet_rate': len(flow_data['packets']) / max(1, max(flow_data['timestamps']) - min(flow_data['timestamps'])) if len(flow_data['timestamps']) > 1 else 0
            }
            
            # Flow characteristics
            characteristics = {
                'protocols': list(flow_data['protocols']),
                'bidirectional': len(set(flow_data['directions'])) > 1,
                'burst_pattern': self._detect_burst_pattern(flow_data['inter_arrival_times']),
                'size_pattern': self._analyze_size_pattern(flow_data['sizes']),
                'timing_regularity': self._analyze_timing_regularity(flow_data['inter_arrival_times'])
            }
            
            analysis['flow_statistics'][flow_id] = stats
            analysis['flow_characteristics'][flow_id] = characteristics
        
        return analysis
    
    def _correlate_flows(self, flows: Dict) -> Dict:
        """Correlate flows to identify potential relationships"""
        correlations = {
            'temporal_correlations': [],
            'size_correlations': [],
            'pattern_correlations': [],
            'suspicious_pairs': []
        }
        
        flow_list = list(flows.items())
        
        for i, (flow1_id, flow1_data) in enumerate(flow_list):
            for j, (flow2_id, flow2_data) in enumerate(flow_list[i+1:], i+1):
                
                # Temporal correlation
                temporal_corr = self._calculate_temporal_correlation(flow1_data, flow2_data)
                if temporal_corr > 0.7:
                    correlations['temporal_correlations'].append({
                        'flow1': flow1_id,
                        'flow2': flow2_id,
                        'correlation': temporal_corr
                    })
                
                # Size correlation
                size_corr = self._calculate_size_correlation(flow1_data, flow2_data)
                if size_corr > 0.6:
                    correlations['size_correlations'].append({
                        'flow1': flow1_id,
                        'flow2': flow2_id,
                        'correlation': size_corr
                    })
                
                # Pattern correlation
                pattern_corr = self._calculate_pattern_correlation(flow1_data, flow2_data)
                if pattern_corr > 0.5:
                    correlations['pattern_correlations'].append({
                        'flow1': flow1_id,
                        'flow2': flow2_id,
                        'correlation': pattern_corr
                    })
                
                # Identify suspicious pairs (high correlation across multiple metrics)
                combined_score = (temporal_corr + size_corr + pattern_corr) / 3
                if combined_score > 0.6:
                    correlations['suspicious_pairs'].append({
                        'flow1': flow1_id,
                        'flow2': flow2_id,
                        'combined_score': combined_score,
                        'temporal': temporal_corr,
                        'size': size_corr,
                        'pattern': pattern_corr
                    })
        
        return correlations
    
    def _timing_correlation(self, flows: Dict) -> Dict:
        """Perform advanced timing correlation analysis"""
        timing_analysis = {
            'synchronized_flows': [],
            'timing_patterns': {},
            'correlation_windows': []
        }
        
        # Analyze timing synchronization between flows
        flow_list = list(flows.items())
        
        for i, (flow1_id, flow1_data) in enumerate(flow_list):
            for j, (flow2_id, flow2_data) in enumerate(flow_list[i+1:], i+1):
                
                # Check for synchronized timing patterns
                sync_score = self._calculate_timing_synchronization(flow1_data, flow2_data)
                if sync_score > 0.8:
                    timing_analysis['synchronized_flows'].append({
                        'flow1': flow1_id,
                        'flow2': flow2_id,
                        'synchronization_score': sync_score
                    })
        
        # Analyze timing patterns for each flow
        for flow_id, flow_data in flows.items():
            if len(flow_data['inter_arrival_times']) > 10:
                timing_analysis['timing_patterns'][flow_id] = {
                    'regularity_score': self._calculate_regularity_score(flow_data['inter_arrival_times']),
                    'burst_intervals': self._identify_burst_intervals(flow_data['inter_arrival_times']),
                    'periodic_behavior': self._detect_periodic_behavior(flow_data['inter_arrival_times'])
                }
        
        return timing_analysis
    
    def _pattern_matching(self, flows: Dict) -> Dict:
        """Match traffic patterns for correlation"""
        patterns = {
            'similar_patterns': [],
            'pattern_clusters': {},
            'anomalous_patterns': []
        }
        
        # Extract patterns from each flow
        flow_patterns = {}
        for flow_id, flow_data in flows.items():
            flow_patterns[flow_id] = self._extract_flow_pattern(flow_data)
        
        # Find similar patterns
        pattern_list = list(flow_patterns.items())
        for i, (flow1_id, pattern1) in enumerate(pattern_list):
            for j, (flow2_id, pattern2) in enumerate(pattern_list[i+1:], i+1):
                similarity = self._calculate_pattern_similarity(pattern1, pattern2)
                if similarity > 0.7:
                    patterns['similar_patterns'].append({
                        'flow1': flow1_id,
                        'flow2': flow2_id,
                        'similarity': similarity
                    })
        
        # Cluster similar patterns
        patterns['pattern_clusters'] = self._cluster_patterns(flow_patterns)
        
        # Identify anomalous patterns
        patterns['anomalous_patterns'] = self._identify_anomalous_patterns(flow_patterns)
        
        return patterns
    
    def _generate_flow_fingerprints(self, flows: Dict) -> Dict:
        """Generate unique fingerprints for each flow"""
        fingerprints = {}
        
        for flow_id, flow_data in flows.items():
            if not flow_data['packets']:
                continue
                
            # Create comprehensive fingerprint
            fingerprint_data = {
                'packet_count': len(flow_data['packets']),
                'size_distribution': self._get_size_distribution(flow_data['sizes']),
                'timing_signature': self._get_timing_signature(flow_data['inter_arrival_times']),
                'protocol_signature': list(flow_data['protocols']),
                'direction_pattern': self._get_direction_pattern(flow_data['directions'])
            }
            
            # Generate hash-based fingerprint
            fingerprint_string = str(fingerprint_data)
            fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]
            
            fingerprints[flow_id] = {
                'fingerprint_hash': fingerprint_hash,
                'characteristics': fingerprint_data
            }
        
        return fingerprints
    
    def _detect_burst_pattern(self, inter_arrival_times: List[float]) -> Dict:
        """Detect burst patterns in traffic"""
        if len(inter_arrival_times) < 5:
            return {'has_bursts': False}
        
        # Define burst threshold (very short intervals)
        burst_threshold = 0.01  # 10ms
        
        bursts = []
        current_burst = []
        
        for interval in inter_arrival_times:
            if interval < burst_threshold:
                current_burst.append(interval)
            else:
                if len(current_burst) >= 3:  # Minimum 3 packets for a burst
                    bursts.append(current_burst)
                current_burst = []
        
        # Add final burst if exists
        if len(current_burst) >= 3:
            bursts.append(current_burst)
        
        return {
            'has_bursts': len(bursts) > 0,
            'burst_count': len(bursts),
            'avg_burst_size': statistics.mean([len(b) for b in bursts]) if bursts else 0,
            'burst_intensity': len(bursts) / len(inter_arrival_times) if inter_arrival_times else 0
        }
    
    def _analyze_size_pattern(self, sizes: List[int]) -> Dict:
        """Analyze packet size patterns"""
        if not sizes:
            return {'pattern': 'no_data'}
        
        size_counter = Counter(sizes)
        most_common = size_counter.most_common(3)
        
        return {
            'dominant_sizes': [size for size, count in most_common],
            'size_variance': statistics.variance(sizes) if len(sizes) > 1 else 0,
            'size_entropy': self._calculate_entropy([count for size, count in size_counter.items()]),
            'mtu_aligned': any(size >= 1460 for size in sizes)  # Check for MTU-sized packets
        }
    
    def _analyze_timing_regularity(self, inter_arrival_times: List[float]) -> Dict:
        """Analyze timing regularity"""
        if len(inter_arrival_times) < 10:
            return {'regularity': 'insufficient_data'}
        
        # Calculate coefficient of variation
        mean_interval = statistics.mean(inter_arrival_times)
        std_interval = statistics.stdev(inter_arrival_times)
        cv = std_interval / mean_interval if mean_interval > 0 else float('inf')
        
        # Determine regularity level
        if cv < 0.2:
            regularity = 'very_regular'
        elif cv < 0.5:
            regularity = 'regular'
        elif cv < 1.0:
            regularity = 'irregular'
        else:
            regularity = 'very_irregular'
        
        return {
            'regularity': regularity,
            'coefficient_of_variation': cv,
            'mean_interval': mean_interval,
            'std_deviation': std_interval
        }
    
    def _calculate_temporal_correlation(self, flow1_data: Dict, flow2_data: Dict) -> float:
        """Calculate temporal correlation between two flows"""
        if not flow1_data['timestamps'] or not flow2_data['timestamps']:
            return 0.0
        
        # Find overlapping time window
        start_time = max(min(flow1_data['timestamps']), min(flow2_data['timestamps']))
        end_time = min(max(flow1_data['timestamps']), max(flow2_data['timestamps']))
        
        if start_time >= end_time:
            return 0.0
        
        # Calculate overlap ratio
        overlap_duration = end_time - start_time
        total_duration = max(max(flow1_data['timestamps']) - min(flow1_data['timestamps']),
                           max(flow2_data['timestamps']) - min(flow2_data['timestamps']))
        
        return overlap_duration / total_duration if total_duration > 0 else 0.0
    
    def _calculate_size_correlation(self, flow1_data: Dict, flow2_data: Dict) -> float:
        """Calculate size correlation between two flows"""
        if not flow1_data['sizes'] or not flow2_data['sizes']:
            return 0.0
        
        # Compare size distributions
        sizes1 = Counter(flow1_data['sizes'])
        sizes2 = Counter(flow2_data['sizes'])
        
        # Calculate Jaccard similarity of size sets
        common_sizes = set(sizes1.keys()).intersection(set(sizes2.keys()))
        total_sizes = set(sizes1.keys()).union(set(sizes2.keys()))
        
        return len(common_sizes) / len(total_sizes) if total_sizes else 0.0
    
    def _calculate_pattern_correlation(self, flow1_data: Dict, flow2_data: Dict) -> float:
        """Calculate pattern correlation between two flows"""
        # Compare protocols
        protocol_similarity = len(flow1_data['protocols'].intersection(flow2_data['protocols'])) / \
                            len(flow1_data['protocols'].union(flow2_data['protocols'])) \
                            if flow1_data['protocols'].union(flow2_data['protocols']) else 0.0
        
        # Compare direction patterns
        dir_similarity = 1.0 if set(flow1_data['directions']) == set(flow2_data['directions']) else 0.5
        
        return (protocol_similarity + dir_similarity) / 2
    
    def _calculate_timing_synchronization(self, flow1_data: Dict, flow2_data: Dict) -> float:
        """Calculate timing synchronization between flows"""
        if len(flow1_data['timestamps']) < 5 or len(flow2_data['timestamps']) < 5:
            return 0.0
        
        # Simple synchronization check: compare timing patterns
        intervals1 = flow1_data['inter_arrival_times'][:10]  # First 10 intervals
        intervals2 = flow2_data['inter_arrival_times'][:10]
        
        if not intervals1 or not intervals2:
            return 0.0
        
        # Calculate correlation coefficient if possible
        try:
            min_len = min(len(intervals1), len(intervals2))
            if min_len < 3:
                return 0.0
            
            # Handle edge cases to prevent numpy warnings
            if min_len < 2:
                return 0.0
            
            arr1 = np.array(intervals1[:min_len])
            arr2 = np.array(intervals2[:min_len])
            
            # Check for zero variance (constant arrays)
            if np.std(arr1) == 0 or np.std(arr2) == 0:
                return 1.0 if np.array_equal(arr1, arr2) else 0.0
            
            corr_coef = np.corrcoef(arr1, arr2)[0, 1]
            return abs(corr_coef) if not np.isnan(corr_coef) else 0.0
        except:
            return 0.0
    
    def _calculate_entropy(self, values: List[int]) -> float:
        """Calculate entropy of a distribution"""
        if not values:
            return 0.0
        
        total = sum(values)
        if total == 0:
            return 0.0
        
        entropy = 0.0
        for value in values:
            if value > 0:
                p = value / total
                entropy -= p * np.log2(p)
        
        return entropy
    
    def _extract_flow_pattern(self, flow_data: Dict) -> Dict:
        """Extract pattern signature from flow"""
        return {
            'size_pattern': tuple(sorted(Counter(flow_data['sizes']).most_common(5))),
            'timing_pattern': self._discretize_timing_pattern(flow_data['inter_arrival_times']),
            'protocol_pattern': tuple(sorted(flow_data['protocols'])),
            'direction_pattern': tuple(flow_data['directions'][:20])  # First 20 directions
        }
    
    def _discretize_timing_pattern(self, intervals: List[float]) -> Tuple:
        """Convert timing intervals to discrete pattern"""
        if not intervals:
            return tuple()
        
        # Discretize intervals into categories
        discretized = []
        for interval in intervals[:20]:  # First 20 intervals
            if interval < 0.001:
                discretized.append('very_fast')
            elif interval < 0.01:
                discretized.append('fast')
            elif interval < 0.1:
                discretized.append('medium')
            elif interval < 1.0:
                discretized.append('slow')
            else:
                discretized.append('very_slow')
        
        return tuple(discretized)
    
    def _calculate_pattern_similarity(self, pattern1: Dict, pattern2: Dict) -> float:
        """Calculate similarity between two patterns"""
        similarities = []
        
        # Size pattern similarity
        if pattern1['size_pattern'] and pattern2['size_pattern']:
            common_sizes = set(dict(pattern1['size_pattern']).keys()).intersection(
                set(dict(pattern2['size_pattern']).keys())
            )
            total_sizes = set(dict(pattern1['size_pattern']).keys()).union(
                set(dict(pattern2['size_pattern']).keys())
            )
            size_sim = len(common_sizes) / len(total_sizes) if total_sizes else 0.0
            similarities.append(size_sim)
        
        # Timing pattern similarity
        timing_sim = len(set(pattern1['timing_pattern']).intersection(set(pattern2['timing_pattern']))) / \
                    len(set(pattern1['timing_pattern']).union(set(pattern2['timing_pattern']))) \
                    if pattern1['timing_pattern'] or pattern2['timing_pattern'] else 0.0
        similarities.append(timing_sim)
        
        # Protocol similarity
        protocol_sim = len(set(pattern1['protocol_pattern']).intersection(set(pattern2['protocol_pattern']))) / \
                      len(set(pattern1['protocol_pattern']).union(set(pattern2['protocol_pattern']))) \
                      if pattern1['protocol_pattern'] or pattern2['protocol_pattern'] else 0.0
        similarities.append(protocol_sim)
        
        return statistics.mean(similarities) if similarities else 0.0
    
    def _cluster_patterns(self, flow_patterns: Dict) -> Dict:
        """Cluster similar flow patterns"""
        clusters = {}
        cluster_id = 0
        
        processed_flows = set()
        
        for flow_id, pattern in flow_patterns.items():
            if flow_id in processed_flows:
                continue
            
            # Start new cluster
            cluster_flows = [flow_id]
            processed_flows.add(flow_id)
            
            # Find similar flows
            for other_flow_id, other_pattern in flow_patterns.items():
                if other_flow_id in processed_flows:
                    continue
                
                similarity = self._calculate_pattern_similarity(pattern, other_pattern)
                if similarity > 0.8:
                    cluster_flows.append(other_flow_id)
                    processed_flows.add(other_flow_id)
            
            if len(cluster_flows) > 1:
                clusters[f"cluster_{cluster_id}"] = cluster_flows
                cluster_id += 1
        
        return clusters
    
    def _identify_anomalous_patterns(self, flow_patterns: Dict) -> List[str]:
        """Identify flows with anomalous patterns"""
        anomalous = []
        
        # Simple anomaly detection based on pattern uniqueness
        pattern_counts = Counter()
        for flow_id, pattern in flow_patterns.items():
            pattern_signature = str(pattern)
            pattern_counts[pattern_signature] += 1
        
        # Flows with unique patterns are potentially anomalous
        for flow_id, pattern in flow_patterns.items():
            pattern_signature = str(pattern)
            if pattern_counts[pattern_signature] == 1:
                anomalous.append(flow_id)
        
        return anomalous
    
    def _get_size_distribution(self, sizes: List[int]) -> Dict:
        """Get size distribution summary"""
        if not sizes:
            return {}
        
        return {
            'mean': statistics.mean(sizes),
            'median': statistics.median(sizes),
            'std': statistics.stdev(sizes) if len(sizes) > 1 else 0,
            'min': min(sizes),
            'max': max(sizes)
        }
    
    def _get_timing_signature(self, intervals: List[float]) -> str:
        """Generate timing signature"""
        if not intervals:
            return "no_timing"
        
        # Create signature from timing characteristics
        mean_interval = statistics.mean(intervals)
        if mean_interval < 0.001:
            return "burst"
        elif mean_interval < 0.01:
            return "fast"
        elif mean_interval < 0.1:
            return "medium"
        elif mean_interval < 1.0:
            return "slow"
        else:
            return "very_slow"
    
    def _get_direction_pattern(self, directions: List[str]) -> str:
        """Get direction pattern summary"""
        if not directions:
            return "no_direction"
        
        inbound_count = directions.count('inbound')
        outbound_count = directions.count('outbound')
        
        if inbound_count > outbound_count * 2:
            return "mostly_inbound"
        elif outbound_count > inbound_count * 2:
            return "mostly_outbound"
        else:
            return "bidirectional"
    
    def _calculate_regularity_score(self, inter_arrival_times: List[float]) -> float:
        """Calculate regularity score for timing intervals"""
        if len(inter_arrival_times) < 3:
            return 0.0
        
        try:
            # Calculate coefficient of variation (lower = more regular)
            mean_interval = statistics.mean(inter_arrival_times)
            if mean_interval == 0:
                return 0.0
            
            std_interval = statistics.stdev(inter_arrival_times)
            cv = std_interval / mean_interval
            
            # Convert to regularity score (0-1, higher = more regular)
            regularity_score = max(0.0, 1.0 - min(cv, 2.0) / 2.0)
            return regularity_score
            
        except (statistics.StatisticsError, ZeroDivisionError):
            return 0.0
    
    def _identify_burst_intervals(self, inter_arrival_times: List[float]) -> List[Dict]:
        """Identify burst intervals in traffic"""
        if len(inter_arrival_times) < 5:
            return []
        
        burst_threshold = 0.01  # 10ms threshold
        bursts = []
        current_burst_start = None
        burst_packet_count = 0
        
        for i, interval in enumerate(inter_arrival_times):
            if interval < burst_threshold:
                if current_burst_start is None:
                    current_burst_start = i
                    burst_packet_count = 1
                else:
                    burst_packet_count += 1
            else:
                if current_burst_start is not None and burst_packet_count >= 3:
                    bursts.append({
                        'start_index': current_burst_start,
                        'end_index': i,
                        'packet_count': burst_packet_count,
                        'duration': sum(inter_arrival_times[current_burst_start:i])
                    })
                current_burst_start = None
                burst_packet_count = 0
        
        return bursts
    
    def _detect_periodic_behavior(self, inter_arrival_times: List[float]) -> Dict:
        """Detect periodic behavior in timing"""
        if len(inter_arrival_times) < 10:
            return {'periodic': False}
        
        try:
            # Simple periodicity detection using autocorrelation
            intervals = np.array(inter_arrival_times[:50])  # Use first 50 intervals
            
            # Calculate autocorrelation
            autocorr = np.correlate(intervals, intervals, mode='full')
            autocorr = autocorr[autocorr.size // 2:]
            
            # Normalize
            autocorr = autocorr / autocorr[0] if autocorr[0] != 0 else autocorr
            
            # Find peaks (potential periods)
            peaks = []
            for i in range(2, min(len(autocorr), 20)):
                if autocorr[i] > 0.5 and autocorr[i] > autocorr[i-1] and autocorr[i] > autocorr[i+1]:
                    peaks.append(i)
            
            return {
                'periodic': len(peaks) > 0,
                'potential_periods': peaks,
                'max_correlation': float(np.max(autocorr[1:])) if len(autocorr) > 1 else 0.0
            }
            
        except Exception:
            return {'periodic': False}

def analyze_traffic_flows(pcap_file: str) -> Dict:
    """Main function to perform traffic flow correlation analysis"""
    correlator = TrafficFlowCorrelator()
    return correlator.analyze_traffic_flows(pcap_file)
