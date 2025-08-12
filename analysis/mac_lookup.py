import pyshark
import asyncio
from collections import defaultdict

def get_mac_info_scapy(pcap_file):
    """Alternative MAC lookup using Scapy - much faster for large files"""
    try:
        from scapy.all import rdpcap, IP, Ether
        
        packets = rdpcap(pcap_file)
        ip_mac_map = {}
        
        # Process ALL packets to get MAC addresses for all IPs
        print(f"Processing {len(packets)} packets to find MAC addresses for all IPs...")
        
        for pkt in packets:
            if IP in pkt and Ether in pkt:
                ip = pkt[IP].src
                mac = pkt[Ether].src
                if ip not in ip_mac_map:
                    ip_mac_map[ip] = mac
                    
                # Also check destination IP
                ip_dst = pkt[IP].dst
                mac_dst = pkt[Ether].dst
                if ip_dst not in ip_mac_map:
                    ip_mac_map[ip_dst] = mac_dst
        
        print(f"Found MAC addresses for {len(ip_mac_map)} unique IPs")
        return [(ip, mac) for ip, mac in ip_mac_map.items()]
        
    except ImportError:
        print("Scapy not available for fast MAC lookup")
        return []
    except Exception as e:
        print(f"Error in Scapy MAC lookup: {e}")
        return []

def get_mac_info(pcap_file):
    mac_data = []
    
    # Try Scapy first (faster)
    mac_data = get_mac_info_scapy(pcap_file)
    if mac_data:
        return mac_data
    
    # Fallback to PyShark if Scapy fails
    try:
        # Set up event loop for PyShark
        asyncio.set_event_loop(asyncio.new_event_loop())
        
        # Use a more efficient filter and limit processing
        cap = pyshark.FileCapture(pcap_file, display_filter="ip", only_summaries=False)
        
        # Use a dictionary to avoid duplicates
        ip_mac_map = {}
        processed_count = 0
        
        print(f"Processing packets with PyShark to find MAC addresses for all IPs...")
        
        for pkt in cap:
            try:
                processed_count += 1
                
                # Check if packet has both IP and Ethernet layers
                if hasattr(pkt, 'ip') and hasattr(pkt, 'eth') and pkt.ip.src and pkt.eth.src:
                    ip = pkt.ip.src
                    mac = pkt.eth.src
                    
                    # Only store if we don't already have this IP
                    if ip not in ip_mac_map:
                        ip_mac_map[ip] = mac
                    
                    # Also check destination IP
                    if hasattr(pkt.ip, 'dst') and hasattr(pkt.eth, 'dst') and pkt.ip.dst and pkt.eth.dst:
                        ip_dst = pkt.ip.dst
                        mac_dst = pkt.eth.dst
                        if ip_dst not in ip_mac_map:
                            ip_mac_map[ip_dst] = mac_dst
                        
            except AttributeError:
                continue
            except Exception as e:
                continue
                
    except Exception as e:
        print(f"Error in MAC lookup: {e}")
        
    finally:
        try:
            cap.close()
        except:
            pass
    
    # Convert to list format
    mac_data = [(ip, mac) for ip, mac in ip_mac_map.items()]
    
    return mac_data
