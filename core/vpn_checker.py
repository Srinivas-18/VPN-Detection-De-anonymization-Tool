import requests
import ipaddress
from config import Config

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # Treat invalid IPs as private to skip them

def check_vpn_status(ip):
    if is_private_ip(ip):
        print(f"[i] Skipping private/internal IP: {ip}")
        return False  # or return "Private" if you want to label it

    try:
        api_key = Config.VPN_API_KEY
        if not api_key:
            print(f"[!] VPN API key not configured")
            return "Error"
        
        url = f"https://vpnapi.io/api/{ip}?key={api_key}"
        res = requests.get(url, timeout=5)
        data = res.json()

        if "security" in data:
            return data["security"].get("vpn", False)
        else:
            print(f"[!] Missing 'security' in response for {ip}")
            print(f"[>] Full response: {data}")
            return "Unknown"

    except requests.exceptions.Timeout:
        print(f"[!] Timeout while checking {ip}")
        return "Timeout"

    except Exception as e:
        print(f"[!] Error checking {ip}: {e}")
        return "Error"
