import requests
from core.packet_processor import extract_ips_from_pcap
from config import Config

def get_geo_info(pcap_file):
    ip_list, _ = extract_ips_from_pcap(pcap_file, return_total=True)
    results = {}

    for ip in ip_list:
        try:
            api_key = Config.IPGEO_API_KEY
            if not api_key:
                results[ip] = {
                    "Country": "Error",
                    "City": "API key not configured",
                    "ISP": "Error"
                }
                continue
            
            url = f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip}"
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
