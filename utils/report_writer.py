import csv
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from typing import Dict, List, Optional

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

def save_comprehensive_excel_report(
    filename: str,
    vpn_results: List,
    total_packets: int,
    timestamp: str,
    deanonym_results: Optional[List] = None,
    geo_data: Optional[Dict] = None,
    mac_data: Optional[Dict] = None,
    payload_data: Optional[Dict] = None,
    ai_analysis: Optional[Dict] = None,
    packet_analysis: Optional[Dict] = None
):
    """
    Create a comprehensive Excel report with multiple sheets:
    - Sheet 1: Main Analysis Results
    - Sheet 2: AI Threat Analysis
    - Sheet 3: Detailed Packet Analysis
    """
    
    # Create workbook and sheets
    wb = Workbook()
    
    # Remove default sheet
    wb.remove(wb.active)
    
    # Create sheets
    main_sheet = wb.create_sheet("Main Analysis")
    ai_sheet = wb.create_sheet("AI Threat Analysis")
    packet_sheet = wb.create_sheet("Packet Analysis")
    
    # Define styles
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
    subheader_font = Font(bold=True, color="000000")
    subheader_fill = PatternFill(start_color="D9E1F2", end_color="D9E1F2", fill_type="solid")
    border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    
    # === SHEET 1: Main Analysis ===
    main_sheet.title = "Main Analysis"
    
    # Headers for main analysis
    headers = [
        "IP Address", "VPN Status", "Fingerprint Info", "Country", 
        "City", "ISP", "MAC Address", "Payload Summary"
    ]
    
    # Write headers
    for col, header in enumerate(headers, 1):
        cell = main_sheet.cell(row=1, column=col, value=header)
        cell.font = header_font
        cell.fill = header_fill
        cell.border = border
        cell.alignment = Alignment(horizontal="center")
    
    # Create data dictionary
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
    
    # Write data rows
    for row_idx, ip in enumerate(sorted(all_data.keys()), 2):
        row_data = [ip]
        for header in headers[1:]:
            row_data.append(all_data[ip].get(header, ""))
        
        for col_idx, value in enumerate(row_data, 1):
            cell = main_sheet.cell(row=row_idx, column=col_idx, value=value)
            cell.border = border
    
    # Add summary section
    summary_row = len(all_data) + 4
    main_sheet.cell(row=summary_row, column=1, value="=== ANALYSIS SUMMARY ===").font = Font(bold=True, size=14)
    
    summary_data = [
        ["Total IPs Analyzed", len(all_data)],
        ["Total Packets Processed", total_packets],
        ["Analysis Timestamp", timestamp],
        ["VPN IPs Detected", sum(1 for data in all_data.values() if data.get("VPN Status") is True)],
        ["Unique Countries", len(set(data.get("Country", "") for data in all_data.values() if data.get("Country")))],
        ["Unique MAC Addresses", len(set(data.get("MAC Address", "") for data in all_data.values() if data.get("MAC Address")))]
    ]
    
    for idx, (label, value) in enumerate(summary_data, summary_row + 1):
        main_sheet.cell(row=idx, column=1, value=label).font = Font(bold=True)
        main_sheet.cell(row=idx, column=2, value=value)
    
    # Auto-adjust column widths
    for column in main_sheet.columns:
        max_length = 0
        column_letter = get_column_letter(column[0].column)
        for cell in column:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(str(cell.value))
            except:
                pass
        adjusted_width = min(max_length + 2, 50)
        main_sheet.column_dimensions[column_letter].width = adjusted_width
    
    # === SHEET 2: AI Threat Analysis ===
    if ai_analysis:
        ai_sheet.title = "AI Threat Analysis"
        
        # Network Behavior Analysis
        row = 1
        ai_sheet.cell(row=row, column=1, value="NETWORK BEHAVIOR ANALYSIS").font = Font(bold=True, size=14)
        ai_sheet.cell(row=row, column=1).fill = subheader_fill
        
        if "network_analysis" in ai_analysis and "error" not in ai_analysis["network_analysis"]:
            row += 2
            for key, value in ai_analysis["network_analysis"].items():
                ai_sheet.cell(row=row, column=1, value=f"{key.replace('_', ' ').title()}:").font = Font(bold=True)
                if isinstance(value, list):
                    ai_sheet.cell(row=row, column=2, value=", ".join(str(item) for item in value))
                else:
                    ai_sheet.cell(row=row, column=2, value=str(value))
                row += 1
        
        # Payload Intelligence Analysis
        row += 2
        ai_sheet.cell(row=row, column=1, value="PAYLOAD INTELLIGENCE ANALYSIS").font = Font(bold=True, size=14)
        ai_sheet.cell(row=row, column=1).fill = subheader_fill
        
        if "payload_analysis" in ai_analysis and "error" not in ai_analysis["payload_analysis"]:
            row += 2
            for key, value in ai_analysis["payload_analysis"].items():
                ai_sheet.cell(row=row, column=1, value=f"{key.replace('_', ' ').title()}:").font = Font(bold=True)
                if isinstance(value, list):
                    ai_sheet.cell(row=row, column=2, value=", ".join(str(item) for item in value))
                else:
                    ai_sheet.cell(row=row, column=2, value=str(value))
                row += 1
        
        # Threat Report
        row += 2
        ai_sheet.cell(row=row, column=1, value="COMPREHENSIVE THREAT REPORT").font = Font(bold=True, size=14)
        ai_sheet.cell(row=row, column=1).fill = subheader_fill
        
        if "threat_report" in ai_analysis:
            row += 2
            threat_report = ai_analysis["threat_report"]
            # Split report into lines and add to sheet
            lines = threat_report.split('\n')
            for line in lines:
                if line.strip():
                    ai_sheet.cell(row=row, column=1, value=line)
                    row += 1
        
        # Auto-adjust column widths for AI sheet
        for column in ai_sheet.columns:
            max_length = 0
            column_letter = get_column_letter(column[0].column)
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 80)
            ai_sheet.column_dimensions[column_letter].width = adjusted_width
    
    # === SHEET 3: Detailed Packet Analysis ===
    if packet_analysis:
        packet_sheet.title = "Packet Analysis"
        
        # Protocol Statistics
        row = 1
        packet_sheet.cell(row=row, column=1, value="PROTOCOL STATISTICS").font = Font(bold=True, size=14)
        packet_sheet.cell(row=row, column=1).fill = subheader_fill
        
        row += 2
        packet_sheet.cell(row=row, column=1, value="Total Packets:").font = Font(bold=True)
        packet_sheet.cell(row=row, column=2, value=packet_analysis.get('total_packets', 0))
        row += 1
        
        packet_sheet.cell(row=row, column=1, value="Average Packet Size:").font = Font(bold=True)
        packet_sheet.cell(row=row, column=2, value=f"{packet_analysis.get('avg_packet_size', 0):.1f} bytes")
        row += 2
        
        # Protocol Distribution
        packet_sheet.cell(row=row, column=1, value="Protocol Distribution:").font = Font(bold=True, size=12)
        packet_sheet.cell(row=row, column=1).fill = PatternFill(start_color="E7E6E6", end_color="E7E6E6", fill_type="solid")
        row += 1
        
        for protocol, count in packet_analysis.get('protocol_stats', {}).items():
            percentage = (count / packet_analysis.get('total_packets', 1)) * 100
            packet_sheet.cell(row=row, column=1, value=f"  {protocol}")
            packet_sheet.cell(row=row, column=2, value=f"{count:,} packets")
            packet_sheet.cell(row=row, column=3, value=f"({percentage:.1f}%)")
            row += 1
        
        # Top Ports
        row += 2
        packet_sheet.cell(row=row, column=1, value="Top Ports Used:").font = Font(bold=True, size=12)
        packet_sheet.cell(row=row, column=1).fill = PatternFill(start_color="E7E6E6", end_color="E7E6E6", fill_type="solid")
        row += 1
        
        for port_info, count in packet_analysis.get('top_ports', {}).items():
            packet_sheet.cell(row=row, column=1, value=f"  {port_info}")
            packet_sheet.cell(row=row, column=2, value=f"{count:,} packets")
            row += 1
        
        # Website Access
        row += 2
        packet_sheet.cell(row=row, column=1, value="WEBSITE ACCESS ANALYSIS").font = Font(bold=True, size=14)
        packet_sheet.cell(row=row, column=1).fill = subheader_fill
        
        websites = packet_analysis.get('top_websites', {})
        if websites:
            row += 2
            packet_sheet.cell(row=row, column=1, value="Most Accessed Websites:").font = Font(bold=True, size=12)
            packet_sheet.cell(row=row, column=1).fill = PatternFill(start_color="E7E6E6", end_color="E7E6E6", fill_type="solid")
            row += 1
            
            for website, count in websites.items():
                packet_sheet.cell(row=row, column=1, value=f"  {website}")
                packet_sheet.cell(row=row, column=2, value=f"{count} queries")
                row += 1
        
        # Potential Passwords
        row += 2
        packet_sheet.cell(row=row, column=1, value="POTENTIAL PASSWORD DETECTION").font = Font(bold=True, size=14)
        packet_sheet.cell(row=row, column=1).fill = PatternFill(start_color="FF6B6B", end_color="FF6B6B", fill_type="solid")
        
        passwords = packet_analysis.get('potential_passwords', [])
        if passwords:
            row += 2
            packet_sheet.cell(row=row, column=1, value=f"Found {len(passwords)} potential password fields!").font = Font(bold=True, color="FF0000")
            row += 2
            
            # Headers for password data
            pwd_headers = ["Type", "Source IP", "Destination IP", "Field", "Value"]
            for col, header in enumerate(pwd_headers, 1):
                cell = packet_sheet.cell(row=row, column=col, value=header)
                cell.font = Font(bold=True)
                cell.fill = PatternFill(start_color="FFE6E6", end_color="FFE6E6", fill_type="solid")
            row += 1
            
            for pwd in passwords:
                packet_sheet.cell(row=row, column=1, value=pwd.get('type', ''))
                packet_sheet.cell(row=row, column=2, value=pwd.get('src_ip', ''))
                packet_sheet.cell(row=row, column=3, value=pwd.get('dst_ip', ''))
                packet_sheet.cell(row=row, column=4, value=pwd.get('field', ''))
                packet_sheet.cell(row=row, column=5, value=pwd.get('value', ''))
                row += 1
        
        # Suspicious Activity
        row += 2
        packet_sheet.cell(row=row, column=1, value="SUSPICIOUS ACTIVITY DETECTION").font = Font(bold=True, size=14)
        packet_sheet.cell(row=row, column=1).fill = PatternFill(start_color="FFA500", end_color="FFA500", fill_type="solid")
        
        suspicious = packet_analysis.get('suspicious_activity', [])
        if suspicious:
            row += 2
            for activity in suspicious:
                severity_color = "FF0000" if activity['severity'] == 'High' else "FFA500" if activity['severity'] == 'Medium' else "00FF00"
                packet_sheet.cell(row=row, column=1, value=f"{activity['type']} ({activity['severity']})").font = Font(bold=True, color=severity_color)
                packet_sheet.cell(row=row, column=2, value=activity['details'])
                row += 1
        
        # Auto-adjust column widths for packet sheet
        for column in packet_sheet.columns:
            max_length = 0
            column_letter = get_column_letter(column[0].column)
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 60)
            packet_sheet.column_dimensions[column_letter].width = adjusted_width
    
    # Save the workbook
    wb.save(filename)
    return filename

