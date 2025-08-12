# core/packet_processor.py

from scapy.all import rdpcap, IP

def extract_ips_from_pcap(pcap_path, return_total=False):
    packets = rdpcap(pcap_path)
    ip_set = set()

    for pkt in packets:
        if IP in pkt:
            ip_set.add(pkt[IP].src)
            ip_set.add(pkt[IP].dst)

    ip_list = list(ip_set)

    if return_total:
        return ip_list, len(packets)
    else:
        return ip_list
