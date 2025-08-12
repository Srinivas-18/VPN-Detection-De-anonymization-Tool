import csv

def save_report(results, filename, total_packets=None, timestamp=None):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "VPN Status"])
        for row in results:
            writer.writerow(row)
        if total_packets is not None:
            writer.writerow([])
            writer.writerow(["Total Packets", total_packets])
        if timestamp:
            writer.writerow(["Timestamp", timestamp])

import csv

def save_full_report(
    filename,
    vpn_results,
    total_packets,
    timestamp,
    deanonym_results=None,
    geo_data=None,
    mac_data=None,
    payload_data=None
):
    with open(filename, "w", newline="", encoding='utf-8') as f:
        writer = csv.writer(f)

        # Create a comprehensive header with all columns
        headers = [
            "IP Address",
            "VPN Status", 
            "Fingerprint Info",
            "Country",
            "City", 
            "ISP",
            "MAC Address",
            "Payload Summary"
        ]
        writer.writerow(headers)

        # Create a dictionary to store all data for each IP
        all_data = {}
        
        # Add VPN results
        for ip, vpn_status in vpn_results:
            all_data[ip] = {"VPN Status": vpn_status}
        
        # Add de-anonymization results
        if deanonym_results:
            for ip, fingerprint in deanonym_results:
                if ip not in all_data:
                    all_data[ip] = {}
                all_data[ip]["Fingerprint Info"] = fingerprint
        
        # Add geolocation data
        if geo_data:
            for ip, info in geo_data.items():
                if ip not in all_data:
                    all_data[ip] = {}
                all_data[ip]["Country"] = info.get("country", "")
                all_data[ip]["City"] = info.get("city", "")
                all_data[ip]["ISP"] = info.get("isp", "")
        
        # Add MAC data
        if mac_data:
            for ip, mac in mac_data.items():
                if ip not in all_data:
                    all_data[ip] = {}
                all_data[ip]["MAC Address"] = mac
        
        # Add payload data
        if payload_data:
            for ip, payload in payload_data.items():
                if ip not in all_data:
                    all_data[ip] = {}
                all_data[ip]["Payload Summary"] = payload
        
        # Write all data rows
        for ip in sorted(all_data.keys()):
            row = [ip]
            for header in headers[1:]:  # Skip IP Address header
                row.append(all_data[ip].get(header, ""))
            writer.writerow(row)
        
        # Add summary information at the end
        writer.writerow([])
        writer.writerow(["=== ANALYSIS SUMMARY ==="])
        writer.writerow(["Total IPs Analyzed", len(all_data)])
        writer.writerow(["Total Packets Processed", total_packets])
        writer.writerow(["Analysis Timestamp", timestamp])
        
        # Count VPNs
        vpn_count = sum(1 for data in all_data.values() if data.get("VPN Status") is True)
        writer.writerow(["VPN IPs Detected", vpn_count])
        
        # Count countries
        countries = set(data.get("Country", "") for data in all_data.values() if data.get("Country"))
        writer.writerow(["Unique Countries", len(countries)])
        
        # Count unique MACs
        macs = set(data.get("MAC Address", "") for data in all_data.values() if data.get("MAC Address"))
        writer.writerow(["Unique MAC Addresses", len(macs)])

