#!/usr/bin/env python3
"""
DNS Leak Detection Module
Detects DNS leaks that can compromise VPN anonymity by revealing real user locations.
"""

import re
from collections import defaultdict, Counter
from typing import Dict, List, Set, Optional
from scapy.all import rdpcap, IP, UDP, DNS, Raw
import ipaddress

class DNSLeakDetector:
    """Detects DNS leaks and queries that bypass VPN tunnels"""
    
    def __init__(self):
        self.public_dns_servers = {
            '8.8.8.8': 'Google DNS',
            '8.8.4.4': 'Google DNS',
            '1.1.1.1': 'Cloudflare DNS',
            '1.0.0.1': 'Cloudflare DNS',
            '208.67.222.222': 'OpenDNS',
            '208.67.220.220': 'OpenDNS',
            '9.9.9.9': 'Quad9 DNS',
            '149.112.112.112': 'Quad9 DNS'
        }
        
        self.isp_dns_patterns = [
            r'.*\.comcast\.net',
            r'.*\.verizon\.net',
            r'.*\.att\.net',
            r'.*\.charter\.com',
            r'.*\.cox\.net',
            r'.*\.centurylink\.net'
        ]
    
    def analyze_dns_leaks(self, pcap_file: str) -> Dict:
        """Comprehensive DNS leak analysis"""
        try:
            packets = rdpcap(pcap_file)
            
            dns_queries = self._extract_dns_queries(packets)
            leak_analysis = self._analyze_potential_leaks(dns_queries)
            geographic_analysis = self._analyze_geographic_leaks(dns_queries)
            timing_analysis = self._analyze_dns_timing(dns_queries)
            
            results = {
                'total_dns_queries': len(dns_queries),
                'dns_servers_used': self._get_dns_servers_used(dns_queries),
                'potential_leaks': leak_analysis,
                'geographic_analysis': geographic_analysis,
                'timing_analysis': timing_analysis,
                'privacy_assessment': self._assess_privacy_risk(dns_queries, leak_analysis),
                'recommendations': self._generate_recommendations(leak_analysis)
            }
            
            return results
            
        except Exception as e:
            return {'error': f"DNS leak analysis failed: {str(e)}"}
    
    def detect_dns_leaks(self, pcap_file: str) -> Dict:
        """Main analysis function called by GUI"""
        return self.analyze_dns_leaks(pcap_file)
    
    def _extract_dns_queries(self, packets) -> List[Dict]:
        """Extract all DNS queries from packet capture"""
        dns_queries = []
        
        for pkt in packets:
            if DNS in pkt:
                try:
                    dns_pkt = pkt[DNS]
                    if dns_pkt.qr == 0:  # Query (not response)
                        query_info = {
                            'timestamp': float(pkt.time),
                            'src_ip': pkt[IP].src if IP in pkt else 'Unknown',
                            'dns_server': pkt[IP].dst if IP in pkt else 'Unknown',
                            'query_name': dns_pkt.qd.qname.decode('utf-8', errors='ignore').rstrip('.') if dns_pkt.qd else 'Unknown',
                            'query_type': dns_pkt.qd.qtype if dns_pkt.qd else 0,
                            'query_class': dns_pkt.qd.qclass if dns_pkt.qd else 0,
                            'packet': pkt
                        }
                        dns_queries.append(query_info)
                except Exception:
                    continue
        
        return dns_queries
    
    def _analyze_potential_leaks(self, dns_queries: List[Dict]) -> Dict:
        """Analyze DNS queries for potential leaks"""
        leak_indicators = {
            'isp_dns_usage': [],
            'public_dns_bypass': [],
            'local_dns_queries': [],
            'suspicious_domains': [],
            'unencrypted_queries': len(dns_queries),  # All captured queries are unencrypted
            'leak_severity': 'low'
        }
        
        for query in dns_queries:
            dns_server = query['dns_server']
            src_ip = query['src_ip']
            query_name = query['query_name']
            
            # Check for ISP DNS usage (potential leak)
            if self._is_isp_dns(dns_server):
                leak_indicators['isp_dns_usage'].append({
                    'dns_server': dns_server,
                    'query': query_name,
                    'timestamp': query['timestamp']
                })
            
            # Check for public DNS bypass
            if dns_server in self.public_dns_servers:
                leak_indicators['public_dns_bypass'].append({
                    'dns_server': dns_server,
                    'provider': self.public_dns_servers[dns_server],
                    'query': query_name,
                    'timestamp': query['timestamp']
                })
            
            # Check for local network DNS queries
            if self._is_local_dns_query(query_name):
                leak_indicators['local_dns_queries'].append({
                    'query': query_name,
                    'dns_server': dns_server,
                    'timestamp': query['timestamp']
                })
            
            # Check for suspicious domains that might reveal identity
            if self._is_suspicious_domain(query_name):
                leak_indicators['suspicious_domains'].append({
                    'domain': query_name,
                    'reason': self._get_suspicion_reason(query_name),
                    'timestamp': query['timestamp']
                })
        
        # Determine leak severity
        leak_indicators['leak_severity'] = self._calculate_leak_severity(leak_indicators)
        
        return leak_indicators
    
    def _analyze_geographic_leaks(self, dns_queries: List[Dict]) -> Dict:
        """Analyze DNS queries for geographic information leaks"""
        geographic_indicators = {
            'country_specific_domains': [],
            'regional_services': [],
            'local_news_sites': [],
            'government_domains': [],
            'geographic_risk_score': 0.0
        }
        
        country_tlds = {
            '.uk': 'United Kingdom', '.de': 'Germany', '.fr': 'France',
            '.ca': 'Canada', '.au': 'Australia', '.jp': 'Japan',
            '.cn': 'China', '.ru': 'Russia', '.in': 'India',
            '.br': 'Brazil', '.mx': 'Mexico', '.it': 'Italy'
        }
        
        for query in dns_queries:
            domain = query['query_name'].lower()
            
            # Check for country-specific TLDs
            for tld, country in country_tlds.items():
                if domain.endswith(tld):
                    geographic_indicators['country_specific_domains'].append({
                        'domain': domain,
                        'country': country,
                        'timestamp': query['timestamp']
                    })
            
            # Check for regional services
            if self._is_regional_service(domain):
                geographic_indicators['regional_services'].append({
                    'domain': domain,
                    'service_type': self._identify_service_type(domain),
                    'timestamp': query['timestamp']
                })
            
            # Check for government domains
            if '.gov' in domain or self._is_government_domain(domain):
                geographic_indicators['government_domains'].append({
                    'domain': domain,
                    'timestamp': query['timestamp']
                })
        
        # Calculate geographic risk score
        geographic_indicators['geographic_risk_score'] = self._calculate_geographic_risk(geographic_indicators)
        
        return geographic_indicators
    
    def _analyze_dns_timing(self, dns_queries: List[Dict]) -> Dict:
        """Analyze DNS query timing patterns"""
        if not dns_queries:
            return {'error': 'No DNS queries to analyze'}
        
        # Group queries by DNS server
        server_queries = defaultdict(list)
        for query in dns_queries:
            server_queries[query['dns_server']].append(query['timestamp'])
        
        timing_analysis = {}
        for server, timestamps in server_queries.items():
            if len(timestamps) > 1:
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                timing_analysis[server] = {
                    'query_count': len(timestamps),
                    'avg_interval': sum(intervals) / len(intervals),
                    'min_interval': min(intervals),
                    'max_interval': max(intervals),
                    'burst_detection': self._detect_dns_bursts(intervals)
                }
        
        return timing_analysis
    
    def _get_dns_servers_used(self, dns_queries: List[Dict]) -> Dict:
        """Get statistics on DNS servers used"""
        server_usage = Counter(query['dns_server'] for query in dns_queries)
        
        server_analysis = {}
        for server, count in server_usage.items():
            server_info = {
                'query_count': count,
                'server_type': self._classify_dns_server(server),
                'privacy_risk': self._assess_server_privacy_risk(server)
            }
            server_analysis[server] = server_info
        
        return server_analysis
    
    def _assess_privacy_risk(self, dns_queries: List[Dict], leak_analysis: Dict) -> Dict:
        """Assess overall privacy risk from DNS usage with enhanced privacy analysis"""
        risk_factors = {
            'unencrypted_queries': len(dns_queries) > 0,
            'isp_dns_usage': len(leak_analysis['isp_dns_usage']) > 0,
            'geographic_leaks': len(leak_analysis['suspicious_domains']) > 0,
            'multiple_dns_servers': len(set(q['dns_server'] for q in dns_queries)) > 2,
            'public_dns_bypass': len(leak_analysis['public_dns_bypass']) > 0,
            'local_network_queries': len(leak_analysis['local_dns_queries']) > 0
        }
        
        # Enhanced privacy scoring with weighted factors
        weighted_score = (
            risk_factors['unencrypted_queries'] * 0.2 +
            risk_factors['isp_dns_usage'] * 0.3 +
            risk_factors['geographic_leaks'] * 0.25 +
            risk_factors['public_dns_bypass'] * 0.15 +
            risk_factors['multiple_dns_servers'] * 0.05 +
            risk_factors['local_network_queries'] * 0.05
        )
        
        # Additional privacy metrics
        unique_domains = len(set(q['query_name'] for q in dns_queries))
        query_diversity = unique_domains / len(dns_queries) if dns_queries else 0
        
        # DNS over HTTPS/TLS detection (simplified)
        encrypted_dns_usage = self._detect_encrypted_dns_usage(dns_queries)
        
        privacy_assessment = {
            'overall_risk_score': weighted_score,
            'risk_level': 'critical' if weighted_score > 0.8 else 'high' if weighted_score > 0.6 else 'medium' if weighted_score > 0.3 else 'low',
            'risk_factors': risk_factors,
            'anonymity_compromise': weighted_score > 0.5,
            'privacy_metrics': {
                'query_diversity': query_diversity,
                'unique_domains_queried': unique_domains,
                'encrypted_dns_detected': encrypted_dns_usage,
                'dns_fingerprinting_risk': self._assess_dns_fingerprinting_risk(dns_queries),
                'temporal_correlation_risk': self._assess_temporal_correlation_risk(dns_queries)
            },
            'detailed_assessment': self._generate_detailed_privacy_assessment(weighted_score, risk_factors, dns_queries)
        }
        
        return privacy_assessment
    
    def _generate_recommendations(self, leak_analysis: Dict) -> List[str]:
        """Generate recommendations to prevent DNS leaks"""
        recommendations = []
        
        if leak_analysis['isp_dns_usage']:
            recommendations.append("Configure VPN to use VPN provider's DNS servers")
            recommendations.append("Disable automatic DNS server assignment")
        
        if leak_analysis['public_dns_bypass']:
            recommendations.append("Block direct access to public DNS servers (8.8.8.8, 1.1.1.1)")
            recommendations.append("Route all DNS traffic through VPN tunnel")
        
        if leak_analysis['unencrypted_queries'] > 0:
            recommendations.append("Use DNS over HTTPS (DoH) or DNS over TLS (DoT)")
            recommendations.append("Consider using encrypted DNS services")
        
        if leak_analysis['suspicious_domains']:
            recommendations.append("Review browsing habits for privacy-sensitive domains")
            recommendations.append("Use privacy-focused search engines")
        
        if leak_analysis['leak_severity'] == 'high':
            recommendations.append("URGENT: Significant DNS leaks detected - review VPN configuration")
            recommendations.append("Consider switching VPN providers or protocols")
        
        return recommendations
    
    def _is_isp_dns(self, dns_server: str) -> bool:
        """Check if DNS server belongs to an ISP"""
        # This is a simplified check - in practice, you'd use a comprehensive database
        try:
            ip = ipaddress.ip_address(dns_server)
            # Check if it's in common ISP ranges (simplified)
            if ip.is_private:
                return True
            # Add more sophisticated ISP detection logic here
            return False
        except:
            return False
    
    def _is_local_dns_query(self, query_name: str) -> bool:
        """Check if DNS query is for local network resources"""
        local_indicators = [
            '.local', '.lan', '.home', '.internal',
            'localhost', 'router', 'gateway'
        ]
        
        return any(indicator in query_name.lower() for indicator in local_indicators)
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain might reveal user identity or location"""
        suspicious_patterns = [
            r'.*bank.*', r'.*government.*', r'.*\.gov',
            r'.*local.*news.*', r'.*weather.*',
            r'.*\.edu', r'.*university.*'
        ]
        
        return any(re.match(pattern, domain.lower()) for pattern in suspicious_patterns)
    
    def _get_suspicion_reason(self, domain: str) -> str:
        """Get reason why domain is considered suspicious"""
        domain_lower = domain.lower()
        
        if 'bank' in domain_lower:
            return "Banking domain may reveal financial institution"
        elif '.gov' in domain_lower:
            return "Government domain reveals jurisdiction"
        elif 'news' in domain_lower:
            return "News site may indicate geographic location"
        elif '.edu' in domain_lower:
            return "Educational domain may reveal institution"
        else:
            return "Domain may reveal personal information"
    
    def _calculate_leak_severity(self, leak_indicators: Dict) -> str:
        """Calculate overall DNS leak severity"""
        severity_score = 0
        
        # Weight different types of leaks
        severity_score += len(leak_indicators['isp_dns_usage']) * 3
        severity_score += len(leak_indicators['public_dns_bypass']) * 2
        severity_score += len(leak_indicators['suspicious_domains']) * 2
        severity_score += len(leak_indicators['local_dns_queries']) * 1
        
        if severity_score >= 10:
            return 'high'
        elif severity_score >= 5:
            return 'medium'
        else:
            return 'low'
    
    def _is_regional_service(self, domain: str) -> bool:
        """Check if domain represents a regional service"""
        regional_indicators = [
            'netflix', 'hulu', 'bbc', 'cbc', 'abc',
            'weather', 'news', 'local', 'city'
        ]
        
        return any(indicator in domain.lower() for indicator in regional_indicators)
    
    def _identify_service_type(self, domain: str) -> str:
        """Identify the type of regional service"""
        domain_lower = domain.lower()
        
        if any(streaming in domain_lower for streaming in ['netflix', 'hulu', 'prime']):
            return "streaming_service"
        elif any(news in domain_lower for news in ['news', 'bbc', 'cnn']):
            return "news_service"
        elif 'weather' in domain_lower:
            return "weather_service"
        else:
            return "unknown_regional"
    
    def _is_government_domain(self, domain: str) -> bool:
        """Check if domain belongs to government"""
        gov_patterns = [
            r'.*\.gov\..*', r'.*government.*', r'.*federal.*',
            r'.*state\..*', r'.*city\..*'
        ]
        
        return any(re.match(pattern, domain.lower()) for pattern in gov_patterns)
    
    def _calculate_geographic_risk(self, geographic_indicators: Dict) -> float:
        """Calculate geographic information leak risk score"""
        risk_score = 0.0
        
        risk_score += len(geographic_indicators['country_specific_domains']) * 0.3
        risk_score += len(geographic_indicators['regional_services']) * 0.2
        risk_score += len(geographic_indicators['government_domains']) * 0.4
        
        return min(risk_score, 1.0)  # Cap at 1.0
    
    def _detect_dns_bursts(self, intervals: List[float]) -> Dict:
        """Detect burst patterns in DNS queries"""
        if len(intervals) < 5:
            return {'bursts': 0}
        
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
            'bursts': bursts,
            'burst_ratio': bursts / len(intervals)
        }
    
    def _classify_dns_server(self, server: str) -> str:
        """Classify DNS server type"""
        if server in self.public_dns_servers:
            return f"public_dns_{self.public_dns_servers[server]}"
        elif self._is_isp_dns(server):
            return "isp_dns"
        else:
            try:
                ip = ipaddress.ip_address(server)
                if ip.is_private:
                    return "private_dns"
                else:
                    return "unknown_public"
            except:
                return "unknown"
    
    def _assess_server_privacy_risk(self, server: str) -> str:
        """Assess privacy risk of using specific DNS server"""
        if server in self.public_dns_servers:
            return "medium"  # Public DNS servers log queries
        elif self._is_isp_dns(server):
            return "high"  # ISP DNS servers can reveal location
        else:
            return "unknown"
    
    def _detect_encrypted_dns_usage(self, dns_queries: List[Dict]) -> Dict:
        """Detect usage of encrypted DNS protocols (DoH/DoT)"""
        encrypted_indicators = {
            'doh_detected': False,
            'dot_detected': False,
            'encrypted_queries': 0,
            'total_queries': len(dns_queries)
        }
        
        for query in dns_queries:
            # Check for DNS over HTTPS indicators (port 443 usage)
            if hasattr(query.get('packet'), 'dport') and query['packet'].dport == 443:
                encrypted_indicators['doh_detected'] = True
                encrypted_indicators['encrypted_queries'] += 1
            
            # Check for DNS over TLS indicators (port 853)
            elif hasattr(query.get('packet'), 'dport') and query['packet'].dport == 853:
                encrypted_indicators['dot_detected'] = True
                encrypted_indicators['encrypted_queries'] += 1
        
        encrypted_indicators['encryption_ratio'] = (
            encrypted_indicators['encrypted_queries'] / encrypted_indicators['total_queries']
            if encrypted_indicators['total_queries'] > 0 else 0
        )
        
        return encrypted_indicators
    
    def _assess_dns_fingerprinting_risk(self, dns_queries: List[Dict]) -> Dict:
        """Assess risk of DNS-based fingerprinting"""
        if not dns_queries:
            return {'risk_level': 'unknown', 'factors': []}
        
        # Analyze query patterns for fingerprinting indicators
        query_domains = [q['query_name'] for q in dns_queries]
        unique_domains = set(query_domains)
        
        fingerprinting_factors = []
        risk_score = 0.0
        
        # Check for unique browsing patterns
        if len(unique_domains) > 50:
            fingerprinting_factors.append("High domain diversity indicates unique browsing pattern")
            risk_score += 0.3
        
        # Check for specific service combinations
        service_indicators = {
            'social_media': any('facebook' in d or 'twitter' in d or 'instagram' in d for d in query_domains),
            'streaming': any('netflix' in d or 'youtube' in d or 'spotify' in d for d in query_domains),
            'work_related': any('office' in d or 'microsoft' in d or 'google' in d for d in query_domains),
            'news': any('news' in d or 'bbc' in d or 'cnn' in d for d in query_domains)
        }
        
        active_services = sum(service_indicators.values())
        if active_services >= 3:
            fingerprinting_factors.append("Multiple service categories create unique usage signature")
            risk_score += 0.2
        
        # Check for timing patterns
        timestamps = [q['timestamp'] for q in dns_queries]
        if len(timestamps) > 10:
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_interval = sum(intervals) / len(intervals)
            if 0.1 < avg_interval < 2.0:  # Regular human-like intervals
                fingerprinting_factors.append("Regular query timing suggests human browsing pattern")
                risk_score += 0.1
        
        return {
            'risk_level': 'high' if risk_score > 0.4 else 'medium' if risk_score > 0.2 else 'low',
            'risk_score': risk_score,
            'factors': fingerprinting_factors,
            'unique_domains': len(unique_domains),
            'service_diversity': active_services
        }
    
    def _assess_temporal_correlation_risk(self, dns_queries: List[Dict]) -> Dict:
        """Assess risk of temporal correlation attacks"""
        if len(dns_queries) < 10:
            return {'risk_level': 'low', 'reason': 'Insufficient data for temporal analysis'}
        
        timestamps = sorted([q['timestamp'] for q in dns_queries])
        
        # Analyze query timing patterns
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        # Check for burst patterns that could be correlated
        burst_count = 0
        for i in range(len(intervals) - 2):
            if intervals[i] < 0.1 and intervals[i+1] < 0.1 and intervals[i+2] < 0.1:
                burst_count += 1
        
        # Check for regular patterns
        regular_intervals = sum(1 for interval in intervals if 0.5 < interval < 2.0)
        regularity_ratio = regular_intervals / len(intervals)
        
        risk_factors = []
        risk_score = 0.0
        
        if burst_count > 3:
            risk_factors.append("Multiple burst patterns detected - vulnerable to timing correlation")
            risk_score += 0.3
        
        if regularity_ratio > 0.6:
            risk_factors.append("Regular timing patterns - predictable behavior")
            risk_score += 0.2
        
        # Check session duration
        session_duration = timestamps[-1] - timestamps[0]
        if session_duration > 3600:  # More than 1 hour
            risk_factors.append("Long session duration increases correlation opportunities")
            risk_score += 0.1
        
        return {
            'risk_level': 'high' if risk_score > 0.4 else 'medium' if risk_score > 0.2 else 'low',
            'risk_score': risk_score,
            'factors': risk_factors,
            'burst_count': burst_count,
            'regularity_ratio': regularity_ratio,
            'session_duration': session_duration
        }
    
    def _generate_detailed_privacy_assessment(self, risk_score: float, risk_factors: Dict, dns_queries: List[Dict]) -> Dict:
        """Generate detailed privacy assessment with actionable insights"""
        assessment = {
            'overall_status': 'CRITICAL' if risk_score > 0.8 else 'HIGH RISK' if risk_score > 0.6 else 'MODERATE RISK' if risk_score > 0.3 else 'LOW RISK',
            'primary_concerns': [],
            'privacy_score': max(0, 100 - int(risk_score * 100)),
            'anonymity_level': 'COMPROMISED' if risk_score > 0.7 else 'WEAK' if risk_score > 0.5 else 'MODERATE' if risk_score > 0.3 else 'STRONG',
            'immediate_actions': [],
            'long_term_recommendations': []
        }
        
        # Identify primary concerns
        if risk_factors['isp_dns_usage']:
            assessment['primary_concerns'].append("ISP DNS servers can log and correlate your activities")
            assessment['immediate_actions'].append("Switch to VPN provider's DNS servers immediately")
        
        if risk_factors['unencrypted_queries']:
            assessment['primary_concerns'].append("All DNS queries are unencrypted and visible to network observers")
            assessment['immediate_actions'].append("Enable DNS over HTTPS (DoH) or DNS over TLS (DoT)")
        
        if risk_factors['geographic_leaks']:
            assessment['primary_concerns'].append("Domain queries reveal geographic location and interests")
            assessment['long_term_recommendations'].append("Use privacy-focused search engines and avoid location-specific sites")
        
        if risk_factors['public_dns_bypass']:
            assessment['primary_concerns'].append("Direct connections to public DNS bypass VPN tunnel")
            assessment['immediate_actions'].append("Configure firewall to block direct DNS connections")
        
        # Additional recommendations based on query patterns
        if len(dns_queries) > 100:
            assessment['long_term_recommendations'].append("Consider using DNS caching to reduce query frequency")
        
        unique_domains = len(set(q['query_name'] for q in dns_queries))
        if unique_domains > 50:
            assessment['long_term_recommendations'].append("High domain diversity creates unique fingerprint - consider using shared/proxy browsing")
        
        return assessment

def detect_dns_leaks(pcap_file: str) -> Dict:
    """Main function to detect DNS leaks"""
    detector = DNSLeakDetector()
    return detector.analyze_dns_leaks(pcap_file)
