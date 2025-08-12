try:
    import pyshark
    import asyncio
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    print("Warning: PyShark not available. Payload inspection will be limited.")

def inspect_payloads(pcap_file):
    payloads = {}
    
    if not PYSHARK_AVAILABLE:
        print("PyShark not available. Cannot perform payload inspection.")
        return payloads
    
    try:
        # Set up event loop for PyShark
        asyncio.set_event_loop(asyncio.new_event_loop())
        
        # Process ALL packets to get payloads for every IP
        cap = pyshark.FileCapture(pcap_file, display_filter="ip", only_summaries=False)
        
        processed_count = 0
        unique_ips_found = 0
        
        print(f"Processing ALL packets for complete payload inspection...")
        
        for pkt in cap:
            try:
                processed_count += 1
                
                if hasattr(pkt, 'ip') and pkt.ip.src:
                    ip = pkt.ip.src
                    
                    # Skip if we already have payload for this IP
                    if ip in payloads:
                        continue
                    
                    # Try to get payload data
                    payload_data = ""
                    
                    # Check for different payload types
                    if hasattr(pkt, 'data') and pkt.data:
                        payload_data = str(pkt.data)
                    elif hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'payload'):
                        payload_data = str(pkt.tcp.payload)
                    elif hasattr(pkt, 'udp') and hasattr(pkt.udp, 'payload'):
                        payload_data = str(pkt.udp.payload)
                    else:
                        # Try to get raw packet data
                        try:
                            raw_data = pkt.get_raw_packet()
                            if raw_data:
                                payload_data = raw_data.hex()[:100]  # First 100 hex chars
                        except:
                            payload_data = "No payload data available"
                    
                    # Store payload data for every packet (even if small)
                    if payload_data and payload_data.strip():
                        payloads[ip] = payload_data[:200]  # Limit to 200 chars
                        unique_ips_found += 1
                        
            except Exception as e:
                continue
                
    except Exception as e:
        print(f"Error in payload inspection: {e}")
        
    finally:
        try:
            cap.close()
        except:
            pass
    
    return payloads
