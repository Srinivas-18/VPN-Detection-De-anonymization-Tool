from scapy.all import rdpcap, IP, TCP

def extract_fingerprints(file_path):
    packets = rdpcap(file_path)
    fingerprints = {}

    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            ttl = pkt[IP].ttl

            window_size = None
            if TCP in pkt:
                window_size = pkt[TCP].window

            if src_ip not in fingerprints:
                fingerprints[src_ip] = {
                    "ttl": ttl,
                    "window_size": window_size,
                    "protocols": set()
                }

            if TCP in pkt:
                fingerprints[src_ip]["protocols"].add("TCP")
            else:
                fingerprints[src_ip]["protocols"].add("Other")

    return fingerprints
