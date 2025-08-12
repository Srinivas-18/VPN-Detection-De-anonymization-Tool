import requests
from core.packet_processor import extract_ips_from_pcap

API_KEY = "8bfb49775bc546b2aff5219404fa64c3"

def get_geo_info(pcap_file):
    ip_list, _ = extract_ips_from_pcap(pcap_file, return_total=True)
    results = {}

    for ip in ip_list:
        try:
            url = f"https://api.ipgeolocation.io/ipgeo?apiKey={API_KEY}&ip={ip}"
            res = requests.get(url, timeout=5)
            data = res.json()
            results[ip] = {
                "Country": data.get("country_name", "N/A"),
                "City": data.get("city", "N/A"),
                "ISP": data.get("isp", "N/A")
            }
        except Exception as e:
            results[ip] = {
                "Country": "Error",
                "City": str(e),
                "ISP": "Error"
            }

    return results
