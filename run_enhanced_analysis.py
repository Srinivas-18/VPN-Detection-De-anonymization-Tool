#!/usr/bin/env python3
"""
Enhanced De-anonymization Analysis Runner
Demonstrates the new encrypted traffic analysis capabilities
"""

import sys
import os
import traceback

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_modules():
    """Test all enhanced de-anonymization modules"""
    print("🚀 ENHANCED VPN DE-ANONYMIZATION TOOL")
    print("=" * 60)
    print("Testing advanced encrypted traffic analysis capabilities")
    print("FOR EDUCATIONAL AND AUTHORIZED RESEARCH PURPOSES ONLY")
    print("=" * 60)
    
    results = {}
    
    # Test 1: Advanced Fingerprinting
    print("\n🔍 Testing Advanced Fingerprinting Module...")
    try:
        from deanon.advanced_fingerprinting import AdvancedFingerprinter
        fingerprinter = AdvancedFingerprinter()
        
        # Test OS detection
        test_ttls = [128, 64, 32, 255]
        for ttl in test_ttls:
            mock_data = {'protocols': set(['TCP']), 'ports': set([80, 443])}
            # Create mock packet structure
            class MockTCP:
                def __init__(self):
                    self.window = 65535
            
            class MockIP:
                def __init__(self, ttl):
                    self.ttl = ttl
            
            class MockPacket:
                def __init__(self, ttl):
                    self.IP = MockIP(ttl)
                    self.TCP = MockTCP()
            
            mock_pkt = MockPacket(ttl)
            os_guess = fingerprinter._guess_os_advanced(mock_pkt, mock_data)
            print(f"   TTL {ttl}: {os_guess}")
        
        results['Advanced Fingerprinting'] = True
        print("   ✅ Advanced Fingerprinting: READY")
        
    except Exception as e:
        print(f"   ❌ Advanced Fingerprinting: FAILED - {e}")
        results['Advanced Fingerprinting'] = False
    
    # Test 2: Traffic Correlation
    print("\n📊 Testing Traffic Correlation Module...")
    try:
        from deanon.traffic_correlation import TrafficCorrelationAnalyzer
        analyzer = TrafficCorrelationAnalyzer()
        
        # Test timing correlation
        timestamps1 = [1.0, 1.1, 1.3, 1.6, 2.0]
        timestamps2 = [1.05, 1.15, 1.35, 1.65, 2.05]
        
        correlation = analyzer._calculate_time_correlation(timestamps1, timestamps2)
        print(f"   Time correlation test: {correlation:.3f}")
        
        results['Traffic Correlation'] = True
        print("   ✅ Traffic Correlation: READY")
        
    except Exception as e:
        print(f"   ❌ Traffic Correlation: FAILED - {e}")
        results['Traffic Correlation'] = False
    
    # Test 3: DNS Leak Detection
    print("\n🌐 Testing DNS Leak Detection Module...")
    try:
        from deanon.dns_leak_detector import DNSLeakDetector
        detector = DNSLeakDetector()
        
        # Test DNS server classification
        test_servers = ["8.8.8.8", "1.1.1.1", "192.168.1.1"]
        for server in test_servers:
            server_type = detector._classify_dns_server(server)
            print(f"   DNS {server}: {server_type}")
        
        results['DNS Leak Detection'] = True
        print("   ✅ DNS Leak Detection: READY")
        
    except Exception as e:
        print(f"   ❌ DNS Leak Detection: FAILED - {e}")
        results['DNS Leak Detection'] = False
    
    # Test 4: Encrypted Traffic Analysis
    print("\n🔐 Testing Encrypted Traffic Analysis Module...")
    try:
        from deanon.encrypted_traffic_analyzer import EncryptedTrafficAnalyzer
        analyzer = EncryptedTrafficAnalyzer()
        
        # Test entropy calculation
        test_data = b"This is plaintext data with low entropy"
        low_entropy = analyzer._calculate_entropy(test_data)
        
        import os
        high_entropy_data = os.urandom(100)
        high_entropy = analyzer._calculate_entropy(high_entropy_data)
        
        print(f"   Low entropy: {low_entropy:.2f}")
        print(f"   High entropy: {high_entropy:.2f}")
        print(f"   VPN ports detected: {len(analyzer.vpn_ports)}")
        
        results['Encrypted Traffic Analysis'] = True
        print("   ✅ Encrypted Traffic Analysis: READY")
        
    except Exception as e:
        print(f"   ❌ Encrypted Traffic Analysis: FAILED - {e}")
        results['Encrypted Traffic Analysis'] = False
    
    # Summary
    print("\n" + "=" * 60)
    print("🎯 MODULE TEST RESULTS")
    print("=" * 60)
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for module, status in results.items():
        icon = "✅" if status else "❌"
        print(f"{icon} {module}")
    
    print(f"\n📊 Overall Status: {passed}/{total} modules ready ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("\n🚀 ALL ENHANCED DE-ANONYMIZATION MODULES READY!")
        demonstrate_capabilities()
    else:
        print("\n⚠️  Some modules failed - check dependencies")
    
    return results

def demonstrate_capabilities():
    """Show the enhanced capabilities"""
    print("\n🔬 ENHANCED DE-ANONYMIZATION CAPABILITIES")
    print("=" * 60)
    
    capabilities = {
        "🔍 Advanced Fingerprinting": [
            "Device identification through TCP options analysis",
            "Behavioral pattern recognition from network activity",
            "Application fingerprinting (browsers, messaging, streaming)",
            "Timing-based device signatures",
            "Protocol sequence analysis"
        ],
        "📊 Traffic Correlation": [
            "Flow correlation for tunnel detection",
            "Cross-correlation timing analysis",
            "VPN/Tor/Proxy pattern recognition",
            "Traffic shaping detection",
            "Encrypted tunnel relationship mapping"
        ],
        "🌐 DNS Leak Detection": [
            "ISP DNS server detection (reveals real location)",
            "Geographic information leak analysis",
            "Privacy risk assessment and scoring",
            "DNS query pattern analysis",
            "Anonymity compromise detection"
        ],
        "🔐 Encrypted Traffic Analysis": [
            "Metadata analysis without decryption",
            "Website fingerprinting through encrypted HTTPS",
            "Application classification from traffic patterns",
            "Side-channel information leakage detection",
            "Entropy analysis for encryption detection"
        ]
    }
    
    total_techniques = 0
    for category, techniques in capabilities.items():
        print(f"\n{category}:")
        for technique in techniques:
            print(f"   ✓ {technique}")
            total_techniques += 1
    
    print(f"\n🎯 TOTAL: {total_techniques} advanced de-anonymization techniques")
    print("\n⚠️  IMPORTANT: Use only for authorized security research and education")

def show_usage_examples():
    """Show how to use the enhanced modules"""
    print("\n📖 USAGE EXAMPLES")
    print("=" * 60)
    
    examples = """
# Example 1: Analyze encrypted VPN traffic
from deanon.encrypted_traffic_analyzer import analyze_encrypted_traffic
results = analyze_encrypted_traffic('captured_vpn_traffic.pcap')

# Example 2: Advanced device fingerprinting
from deanon.advanced_fingerprinting import analyze_advanced_fingerprints
fingerprints = analyze_advanced_fingerprints('network_capture.pcap')

# Example 3: Traffic flow correlation
from deanon.traffic_correlation import analyze_traffic_correlation
correlations = analyze_traffic_correlation('suspicious_traffic.pcap')

# Example 4: DNS leak detection
from deanon.dns_leak_detector import detect_dns_leaks
dns_leaks = detect_dns_leaks('dns_traffic.pcap')
"""
    
    print(examples)
    print("💡 All functions accept PCAP file paths and return detailed analysis dictionaries")

def main():
    """Main execution function"""
    try:
        # Test all modules
        results = test_modules()
        
        # Show usage examples
        show_usage_examples()
        
        print("\n" + "=" * 60)
        print("🎓 CYBERSECURITY STUDENT READY FOR ADVANCED ANALYSIS")
        print("=" * 60)
        print("Your enhanced VPN de-anonymization tool now includes:")
        print("• Advanced encrypted traffic analysis")
        print("• Sophisticated fingerprinting techniques")
        print("• Traffic correlation and flow matching")
        print("• DNS leak detection and privacy assessment")
        print("\nReady to analyze encrypted VPN traffic and masked IP data!")
        
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        print("\nStacktrace:")
        traceback.print_exc()

if __name__ == "__main__":
    main()
