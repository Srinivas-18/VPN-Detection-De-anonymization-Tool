import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from core.packet_processor import extract_ips_from_pcap, analyze_packet_details
from core.vpn_checker import check_vpn_status
from utils.report_writer import save_report, save_full_report, save_comprehensive_excel_report
from deanon.fingerprint_extractor import extract_fingerprints
from deanon.deanonymizer import classify_fingerprint
from deanon.encrypted_traffic_analyzer import EncryptedTrafficAnalyzer
from deanon.advanced_fingerprinting import AdvancedFingerprinter
from deanon.traffic_flow_correlator import TrafficFlowCorrelator
from deanon.dns_leak_detector import DNSLeakDetector
from deanon.real_ip_detector import RealIPDetector
from analysis.geo_locator import get_geo_info
from analysis.mac_lookup import get_mac_info
from analysis.payload_inspector import inspect_payloads
from analysis.ai_analyzer import get_ai_analyzer

import threading
import datetime
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt


def launch_gui():
    def select_file():
        file_path = filedialog.askopenfilename(filetypes=[
            ("PCAP files", "*.pcap *.pcapng"),
            ("All files", "*.*")
        ])
        if file_path:
            file_label.config(text=file_path)
            app.file_path = file_path

    def analyze_file():
        if not hasattr(app, "file_path"):
            messagebox.showerror("Error", "Please select a .pcap file first.")
            return

        for item in tree.get_children():
            tree.delete(item)
        for item in deanonym_tree.get_children():
            deanonym_tree.delete(item)
        chart_frame.pack_forget()
        progress_label.config(text="Extracting IPs...")

        def run_analysis():
            try:
                ip_list, total_packets = extract_ips_from_pcap(app.file_path, return_total=True)
                app.results = []
                app.total_packets = total_packets
                for idx, ip in enumerate(ip_list, 1):
                    vpn_status = check_vpn_status(ip)
                    app.results.append((ip, vpn_status))
                    app.after(0, lambda ip=ip, vpn_status=vpn_status:
                              tree.insert("", "end", values=(ip, vpn_status)))
                    progress_label.config(text=f"[{idx}/{len(ip_list)}] {ip} → VPN: {vpn_status}")
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                app.timestamp = timestamp
                progress_label.config(text=f"✅ VPN detection completed at {timestamp} ({total_packets} packets)")
                app.after(0, lambda: show_chart_popup(app.results))
            except Exception as e:
                messagebox.showerror("Error", str(e))

        threading.Thread(target=run_analysis, daemon=True).start()

    def save_to_csv():
        if not hasattr(app, "results"):
            messagebox.showwarning("No Data", "Analyze a file first.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".csv")
        if file_path:
            save_report(app.results, file_path, app.total_packets, app.timestamp)
            messagebox.showinfo("Saved", f"Report saved to {file_path}")

    def save_full_csv():
        if not hasattr(app, "results") or not hasattr(app, "full_analysis"):
            messagebox.showwarning("No Data", "Run full analysis first.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".csv")

        if not isinstance(file_path, str) or file_path.strip() == "":
            messagebox.showerror("Error", "Invalid file path.")
            return

        try:
            save_full_report(
                file_path,
                app.results,
                app.total_packets,
                app.timestamp,
                deanonym_results=[(ip, data.get("Fingerprint", "")) for ip, data in app.full_analysis.items() if "Fingerprint" in data],
                geo_data={ip: {
                    "country": data.get("Country", ""),
                    "city": data.get("City", ""),
                    "isp": data.get("ISP", "")
                } for ip, data in app.full_analysis.items() if any(k in data for k in ["Country", "City", "ISP"])},
                mac_data={ip: data.get("MAC") for ip, data in app.full_analysis.items() if "MAC" in data},
                payload_data={ip: str(data.get("Payload", "")) for ip, data in app.full_analysis.items() if "Payload" in data}
            )


            messagebox.showinfo("Saved", f"Full report saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def save_comprehensive_excel():
        if not hasattr(app, "results"):
            messagebox.showwarning("No Data", "Analyze a file first.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")]
        )

        if not isinstance(file_path, str) or file_path.strip() == "":
            messagebox.showerror("Error", "Invalid file path.")
            return

        try:
            # Prepare data for comprehensive report
            deanonym_results = []
            geo_data = {}
            mac_data = {}
            payload_data = {}
            ai_analysis = {}
            packet_analysis = {}
            
            # Get existing analysis data
            if hasattr(app, "full_analysis"):
                deanonym_results = [(ip, data.get("Fingerprint", "")) for ip, data in app.full_analysis.items() if "Fingerprint" in data]
                geo_data = {ip: {
                    "country": data.get("Country", ""),
                    "city": data.get("City", ""),
                    "isp": data.get("ISP", "")
                } for ip, data in app.full_analysis.items() if any(k in data for k in ["Country", "City", "ISP"])}
                mac_data = {ip: data.get("MAC") for ip, data in app.full_analysis.items() if "MAC" in data}
                payload_data = {ip: str(data.get("Payload", "")) for ip, data in app.full_analysis.items() if "Payload" in data}
            
            # Get AI analysis data if available
            if hasattr(app, "ai_analysis_results"):
                ai_analysis = app.ai_analysis_results
            
            # Get packet analysis data if available
            if hasattr(app, "packet_analysis_results"):
                packet_analysis = app.packet_analysis_results
            
            # Get enhanced analysis data if available
            enhanced_analysis = None
            if hasattr(app, "enhanced_analysis"):
                enhanced_analysis = app.enhanced_analysis
            
            # Create comprehensive Excel report
            save_comprehensive_excel_report(
                file_path,
                app.results,
                app.total_packets,
                app.timestamp,
                deanonym_results=deanonym_results,
                geo_data=geo_data,
                mac_data=mac_data,
                payload_data=payload_data,
                ai_analysis=ai_analysis,
                packet_analysis=packet_analysis,
                enhanced_analysis=enhanced_analysis
            )

            messagebox.showinfo("Saved", f"Comprehensive Excel report saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def show_chart_popup(data):
        popup = tk.Toplevel(app)
        popup.title("📊 VPN Detection Summary")
        popup.geometry("400x400")

        vpn_count = sum(1 for _, v in data if v is True)
        non_vpn_count = sum(1 for _, v in data if v is False)
        error_count = sum(1 for _, v in data if v == "Error")

        labels = ["VPN", "Non-VPN", "Error"]
        values = [vpn_count, non_vpn_count, error_count]
        colors = ["red", "green", "gray"]

        fig, ax = plt.subplots(figsize=(4, 4))
        ax.pie(values, labels=labels, autopct="%1.1f%%", startangle=140, colors=colors)
        ax.set_title("VPN Detection Pie Chart")

        chart_canvas = FigureCanvasTkAgg(fig, master=popup)
        chart_canvas.draw()
        chart_canvas.get_tk_widget().pack()

    def run_deanonymization():
        if not hasattr(app, "results"):
            messagebox.showwarning("No Data", "Run VPN detection first.")
            return

        vpn_ips = [ip for ip, is_vpn in app.results if is_vpn is True]
        if not vpn_ips:
            messagebox.showinfo("No VPN IPs", "No IPs detected as VPN.")
            return

        progress_label.config(text="🧠 De-anonymizing VPN IPs...")

        def worker():
            fingerprints = extract_fingerprints(app.file_path)
            deanonymized = []
            for ip in vpn_ips:
                if ip in fingerprints:
                    info = classify_fingerprint(fingerprints[ip])
                    deanonymized.append((ip, info))

            def update_table():
                for ip, info in deanonymized:
                    deanonym_tree.insert("", "end", values=(ip, info))
                    app.full_analysis.setdefault(ip, {})["Fingerprint"] = info
                progress_label.config(text=f"✅ De-anonymization done ({len(deanonymized)} results)")

            if not hasattr(app, "full_analysis"):
                app.full_analysis = {}
            app.after(0, update_table)

        threading.Thread(target=worker, daemon=True).start()

    def open_advanced_analysis():
        if not hasattr(app, "file_path"):
            messagebox.showerror("Missing File", "Please select a PCAP file first.")
            return

        popup = tk.Toplevel(app)
        popup.title("⚙️ Advanced Analysis")
        popup.geometry("350x250")
        popup.configure(bg="#1e1e2f")

        def run_geo():
            popup.destroy()
            progress_label.config(text="🌐 Running Geolocation analysis...")
            def worker():
                geo_data = get_geo_info(app.file_path)
                if not hasattr(app, "full_analysis"):
                    app.full_analysis = {}
                for ip, info in geo_data.items():
                    app.full_analysis.setdefault(ip, {}).update(info)
                app.after(0, lambda: progress_label.config(text="✅ Geolocation analysis complete"))
                app.after(0, lambda: show_geo_popup(geo_data))
            threading.Thread(target=worker, daemon=True).start()

        def run_mac():
            popup.destroy()
            progress_label.config(text="🔍 Running MAC address lookup (processing all packets)...")
            def worker():
                try:
                    # Get total IPs first for comparison
                    ip_list, _ = extract_ips_from_pcap(app.file_path, return_total=True)
                    total_ips = len(ip_list)
                    
                    # Update progress
                    app.after(0, lambda: progress_label.config(text=f"🔍 Processing {total_ips} IPs for MAC addresses..."))
                    
                    mac_data = get_mac_info(app.file_path)
                    if not hasattr(app, "full_analysis"):
                        app.full_analysis = {}
                    for ip, mac in mac_data:
                        app.full_analysis.setdefault(ip, {})["MAC"] = mac
                    
                    # Show comparison
                    found_ips = len(mac_data)
                    if found_ips == total_ips:
                        app.after(0, lambda: progress_label.config(text=f"✅ MAC lookup complete ({found_ips}/{total_ips} IPs found) - ALL IPs covered!"))
                    else:
                        app.after(0, lambda: progress_label.config(text=f"⚠️ MAC lookup complete ({found_ips}/{total_ips} IPs found) - Some IPs may not have MAC data"))
                    app.after(0, lambda: show_mac_popup(mac_data))
                except Exception as e:
                    app.after(0, lambda: progress_label.config(text=f"❌ MAC lookup failed: {str(e)}"))
            threading.Thread(target=worker, daemon=True).start()

        def run_payload():
            popup.destroy()
            progress_label.config(text="📦 Inspecting packet payloads (complete analysis)...")
            def worker():
                try:
                    # Get total IPs for comparison
                    ip_list, _ = extract_ips_from_pcap(app.file_path, return_total=True)
                    total_ips = len(ip_list)
                    
                    # Update progress
                    app.after(0, lambda: progress_label.config(text=f"📦 Processing ALL packets for payloads ({total_ips} IPs)..."))
                    
                    payload_data = inspect_payloads(app.file_path)
                    if not hasattr(app, "full_analysis"):
                        app.full_analysis = {}
                    for ip, payload in payload_data.items():
                        app.full_analysis.setdefault(ip, {})["Payload"] = payload
                    
                    # Show results
                    found_ips = len(payload_data)
                    if found_ips > 0:
                        app.after(0, lambda: progress_label.config(text=f"✅ Payload inspection complete ({found_ips} IPs with payloads found)"))
                    else:
                        app.after(0, lambda: progress_label.config(text="⚠️ Payload inspection complete - No meaningful payloads found"))
                    app.after(0, lambda: show_payload_popup(payload_data))
                except Exception as e:
                    app.after(0, lambda: progress_label.config(text=f"❌ Payload inspection failed: {str(e)}"))
            threading.Thread(target=worker, daemon=True).start()

        def run_detailed_analysis():
            popup.destroy()
            progress_label.config(text="📊 Running Detailed Packet Analysis...")
            def worker():
                try:
                    app.after(0, lambda: progress_label.config(text="📊 Analyzing packet protocols, websites, and potential passwords..."))
                    
                    packet_analysis = analyze_packet_details(app.file_path)
                    
                    if "error" in packet_analysis:
                        app.after(0, lambda: progress_label.config(text=f"❌ Detailed analysis failed: {packet_analysis['error']}"))
                        return
                    
                    # Store packet analysis results for comprehensive report
                    app.packet_analysis_results = packet_analysis
                    
                    app.after(0, lambda: progress_label.config(text="✅ Detailed packet analysis complete"))
                    app.after(0, lambda: show_detailed_analysis_popup(packet_analysis))
                    
                except Exception as e:
                    app.after(0, lambda: progress_label.config(text=f"❌ Detailed analysis failed: {str(e)}"))
            
            threading.Thread(target=worker, daemon=True).start()

        def run_enhanced_deanonymization():
            popup.destroy()
            progress_label.config(text="🔐 Running Enhanced De-anonymization Analysis...")
            
            def worker():
                try:
                    # Initialize enhanced analyzers
                    encrypted_analyzer = EncryptedTrafficAnalyzer()
                    dns_detector = DNSLeakDetector()
                    real_ip_detector = RealIPDetector()
                    
                    # Run enhanced analysis
                    app.after(0, lambda: progress_label.config(text="🔐 Analyzing encrypted VPN traffic..."))
                    encrypted_results = encrypted_analyzer.analyze_encrypted_traffic(app.file_path)
                    
                    app.after(0, lambda: progress_label.config(text="🌐 DNS leak detection..."))
                    dns_results = dns_detector.detect_dns_leaks(app.file_path)
                    
                    app.after(0, lambda: progress_label.config(text="🔍 Detecting real IP addresses..."))
                    real_ip_results = real_ip_detector.detect_real_ip_from_pcap(app.file_path)
                    
                    app.after(0, lambda: progress_label.config(text="🔬 Advanced device fingerprinting..."))
                    
                    # Advanced Device Fingerprinting
                    fingerprinter = AdvancedFingerprinter()
                    fingerprint_results = fingerprinter.analyze_advanced_fingerprints(app.file_path)
                    
                    app.after(0, lambda: progress_label.config(text="🔗 Traffic flow correlation..."))
                    
                    # Traffic Flow Correlation
                    flow_correlator = TrafficFlowCorrelator()
                    flow_results = flow_correlator.analyze_traffic_flows(app.file_path)
                    
                    app.after(0, lambda: progress_label.config(text="📊 Extracting encrypted data..."))
                    
                    # Extract encrypted data
                    from simple_extract_encrypted import extract_xvpn_encrypted_data
                    encrypted_packets = extract_xvpn_encrypted_data(app.file_path)
                    
                    # Store enhanced analysis results
                    app.enhanced_analysis = {
                        'real_ip_detection': real_ip_results,
                        'dns_leaks': dns_results,
                        'encrypted_traffic': encrypted_results,
                        'advanced_fingerprints': fingerprint_results,
                        'traffic_flows': flow_results,
                        'encrypted_data_extraction': {
                            'total_encrypted_packets': len(encrypted_packets) if encrypted_packets else 0,
                            'sample_packets': encrypted_packets[:5] if encrypted_packets else []
                        }
                    }
                    
                    # Initialize full_analysis if it doesn't exist
                    if not hasattr(app, 'full_analysis'):
                        app.full_analysis = {}
                    
                    # Merge with full analysis data for detected VPN IPs
                    detected_vpn_ips = real_ip_results.get('vpn_ips_detected', [])
                    if detected_vpn_ips:
                        for vpn_ip in detected_vpn_ips:
                            app.full_analysis.setdefault(vpn_ip, {})["Real_IP_Detection"] = real_ip_results
                            app.full_analysis.setdefault(vpn_ip, {})["DNS_Leaks"] = dns_results
                            app.full_analysis.setdefault(vpn_ip, {})["Encrypted_Traffic"] = encrypted_results
                            app.full_analysis.setdefault(vpn_ip, {})["Advanced_Fingerprints"] = fingerprint_results
                            app.full_analysis.setdefault(vpn_ip, {})["Traffic_Flows"] = flow_results
                            app.full_analysis.setdefault(vpn_ip, {})["Encrypted_Packets"] = len(encrypted_packets) if encrypted_packets else 0
                            
                            if real_ip_results.get('potential_real_ips'):
                                app.full_analysis[vpn_ip]["Real_IP_Detected"] = "Yes"
                                app.full_analysis[vpn_ip]["Potential_Real_IPs"] = real_ip_results['potential_real_ips']
                    
                    app.after(0, lambda: progress_label.config(text="✅ Enhanced de-anonymization complete"))
                    app.after(0, lambda: show_enhanced_analysis_popup(app.enhanced_analysis))
                    
                except Exception as e:
                    app.after(0, lambda: progress_label.config(text=f"❌ Enhanced analysis failed: {str(e)}"))
            
            threading.Thread(target=worker, daemon=True).start()

        def run_ai_analysis(ai_analyzer):
            popup.destroy()
            progress_label.config(text="🤖 Running AI Threat Analysis...")
            
            def worker():
                try:
                    # Check if we have VPN analysis data
                    if not hasattr(app, "results") or not app.results:
                        app.after(0, lambda: progress_label.config(text="❌ No VPN analysis data available. Run VPN detection first."))
                        return
                    
                    # Combine VPN results with full analysis data
                    combined_analysis = {}
                    
                    # First, add VPN detection results
                    for ip, vpn_status in app.results:
                        combined_analysis[ip] = {"VPN Status": vpn_status}
                    
                    # Then, merge with full analysis data if available
                    if hasattr(app, "full_analysis") and app.full_analysis:
                        for ip, data in app.full_analysis.items():
                            if ip in combined_analysis:
                                combined_analysis[ip].update(data)
                            else:
                                combined_analysis[ip] = data
                    
                    # Include enhanced analysis if available
                    if hasattr(app, "enhanced_analysis") and app.enhanced_analysis:
                        combined_analysis["enhanced_deanonymization"] = app.enhanced_analysis
                    
                    # Get payload data if available
                    payload_data = {}
                    for ip, data in combined_analysis.items():
                        if isinstance(data, dict) and "Payload" in data:
                            payload_data[ip] = data["Payload"]
                    
                    # Run AI analysis
                    app.after(0, lambda: progress_label.config(text="🤖 Analyzing network behavior with AI..."))
                    network_analysis = ai_analyzer.analyze_network_behavior(combined_analysis)
                    
                    app.after(0, lambda: progress_label.config(text="🤖 Analyzing payload intelligence..."))
                    payload_analysis = ai_analyzer.analyze_payload_intelligence(payload_data)
                    
                    app.after(0, lambda: progress_label.config(text="🤖 Generating comprehensive threat report..."))
                    threat_report = ai_analyzer.generate_threat_report(combined_analysis, payload_data)
                    
                    # Store AI analysis results for comprehensive report
                    app.ai_analysis_results = {
                        "network_analysis": network_analysis,
                        "payload_analysis": payload_analysis,
                        "threat_report": threat_report
                    }
                    
                    # Show results
                    app.after(0, lambda: progress_label.config(text="✅ AI Threat Analysis complete"))
                    app.after(0, lambda: show_ai_analysis_popup(network_analysis, payload_analysis, threat_report))
                    
                except Exception as e:
                    app.after(0, lambda: progress_label.config(text=f"❌ AI analysis failed: {str(e)}"))
            
            threading.Thread(target=worker, daemon=True).start()

        tk.Button(popup, text="🌐 Geolocation", command=run_geo, bg="#3a3a5c", fg="white", width=25).pack(pady=10)
        tk.Button(popup, text="🔍 MAC Address Lookup", command=run_mac, bg="#3a3a5c", fg="white", width=25).pack(pady=10)
        tk.Button(popup, text="📦 Payload Inspection", command=run_payload, bg="#3a3a5c", fg="white", width=25).pack(pady=10)
        tk.Button(popup, text="📊 Detailed Packet Analysis", command=run_detailed_analysis, bg="#4CAF50", fg="white", width=25).pack(pady=10)
        tk.Button(popup, text="🔐 Enhanced De-anonymization", command=run_enhanced_deanonymization, bg="#e74c3c", fg="white", width=25).pack(pady=10)
        
        # Add AI Analysis button if API key is available
        try:
            ai_analyzer = get_ai_analyzer()
            if ai_analyzer:
                ai_button = tk.Button(popup, text="🤖 AI Threat Analysis", command=lambda: run_ai_analysis(ai_analyzer), 
                                    bg="#ff6b35", fg="white", width=25, font=("Arial", 10, "bold"))
                ai_button.pack(pady=10)
                print("✅ AI Threat Analysis button created and packed")
            else:
                print("❌ AI Analyzer is None - button not added")
                # Add a placeholder button to show the issue
                placeholder_button = tk.Button(popup, text="❌ AI Not Available", 
                                             bg="#666666", fg="white", width=25, state="disabled")
                placeholder_button.pack(pady=10)
        except Exception as e:
            print(f"❌ Error getting AI analyzer: {e}")
            # Add error button for debugging
            error_button = tk.Button(popup, text="🤖 AI Error (Click for details)", 
                                   command=lambda: messagebox.showerror("AI Error", str(e)), 
                                   bg="#cc0000", fg="white", width=25)
            error_button.pack(pady=10)

    def show_geo_popup(geo_data):
        popup = tk.Toplevel(app)
        popup.title("🌐 Geolocation Results")
        popup.geometry("600x500")
        popup.configure(bg="#1e1e2f")

        # Title
        tk.Label(popup, text="🌐 Geolocation Analysis Results", font=("Helvetica", 16, "bold"), 
                fg="white", bg="#1e1e2f").pack(pady=10)

        # Create treeview for data
        geo_tree = ttk.Treeview(popup, columns=("IP", "Country", "City", "ISP"), show="headings", height=15)
        geo_tree.heading("IP", text="IP Address")
        geo_tree.heading("Country", text="Country")
        geo_tree.heading("City", text="City")
        geo_tree.heading("ISP", text="ISP")
        
        # Set column widths
        geo_tree.column("IP", width=150)
        geo_tree.column("Country", width=150)
        geo_tree.column("City", width=150)
        geo_tree.column("ISP", width=150)
        
        geo_tree.pack(padx=20, pady=10, fill="both", expand=True)

        # Add data to treeview
        for ip, info in geo_data.items():
            geo_tree.insert("", "end", values=(
                ip,
                info.get("Country", "N/A"),
                info.get("City", "N/A"),
                info.get("ISP", "N/A")
            ))

        # Close button
        tk.Button(popup, text="Close", command=popup.destroy, bg="#3a3a5c", fg="white").pack(pady=10)

    def show_ai_analysis_popup(network_analysis, payload_analysis, threat_report):
        popup = tk.Toplevel(app)
        popup.title("🤖 AI Threat Analysis Results")
        popup.geometry("900x700")
        popup.configure(bg="#1e1e2f")

        # Title
        tk.Label(popup, text="🤖 AI Threat Analysis Results", font=("Helvetica", 16, "bold"), 
                fg="white", bg="#1e1e2f").pack(pady=10)

        # Create notebook for tabs
        notebook = ttk.Notebook(popup)
        notebook.pack(padx=20, pady=10, fill="both", expand=True)

        # Tab 1: Network Behavior Analysis
        tab1 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab1, text="Network Analysis")
        
        network_text = tk.Text(tab1, bg="#2a2a3a", fg="lightgreen", font=("Courier", 10), wrap="word")
        network_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display network analysis
        if "error" not in network_analysis:
            network_text.insert("end", "🔍 NETWORK BEHAVIOR ANALYSIS\n")
            network_text.insert("end", "=" * 50 + "\n\n")
            for key, value in network_analysis.items():
                network_text.insert("end", f"📊 {key.replace('_', ' ').title()}:\n")
                if isinstance(value, list):
                    for item in value:
                        network_text.insert("end", f"  • {item}\n")
                else:
                    network_text.insert("end", f"  {value}\n")
                network_text.insert("end", "\n")
        else:
            network_text.insert("end", f"❌ Error: {network_analysis['error']}")

        # Tab 2: Payload Intelligence Analysis
        tab2 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab2, text="Payload Analysis")
        
        payload_text = tk.Text(tab2, bg="#2a2a3a", fg="lightblue", font=("Courier", 10), wrap="word")
        payload_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display payload analysis
        if "error" not in payload_analysis:
            payload_text.insert("end", "🔍 PAYLOAD INTELLIGENCE ANALYSIS\n")
            payload_text.insert("end", "=" * 50 + "\n\n")
            for key, value in payload_analysis.items():
                payload_text.insert("end", f"📦 {key.replace('_', ' ').title()}:\n")
                if isinstance(value, list):
                    for item in value:
                        payload_text.insert("end", f"  • {item}\n")
                else:
                    payload_text.insert("end", f"  {value}\n")
                payload_text.insert("end", "\n")
        else:
            payload_text.insert("end", f"❌ Error: {payload_analysis['error']}")

        # Tab 3: Threat Report
        tab3 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab3, text="Threat Report")
        
        threat_text = tk.Text(tab3, bg="#2a2a3a", fg="orange", font=("Courier", 10), wrap="word")
        threat_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display threat report
        threat_text.insert("end", "🚨 COMPREHENSIVE THREAT REPORT\n")
        threat_text.insert("end", "=" * 50 + "\n\n")
        threat_text.insert("end", threat_report)

        # Close button
        tk.Button(popup, text="Close", command=popup.destroy, bg="#3a3a5c", fg="white").pack(pady=10)

    def show_mac_popup(mac_data):
        popup = tk.Toplevel(app)
        popup.title("🔍 MAC Address Lookup Results")
        popup.geometry("800x600")
        popup.configure(bg="#1e1e2f")

        # Title
        tk.Label(popup, text="🔍 MAC Address Lookup Results", font=("Helvetica", 16, "bold"), 
                fg="white", bg="#1e1e2f").pack(pady=10)

        # Analyze MAC distribution
        mac_to_ips = {}
        for ip, mac in mac_data:
            if mac not in mac_to_ips:
                mac_to_ips[mac] = []
            mac_to_ips[mac].append(ip)
        
        # Create notebook for tabs
        notebook = ttk.Notebook(popup)
        notebook.pack(padx=20, pady=10, fill="both", expand=True)

        # Tab 1: All IP-MAC pairs
        tab1 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab1, text="All IP-MAC Pairs")
        
        mac_tree = ttk.Treeview(tab1, columns=("IP", "MAC"), show="headings", height=15)
        mac_tree.heading("IP", text="IP Address")
        mac_tree.heading("MAC", text="MAC Address")
        
        mac_tree.column("IP", width=200)
        mac_tree.column("MAC", width=250)
        
        mac_tree.pack(padx=20, pady=10, fill="both", expand=True)

        # Add data to treeview
        for ip, mac in mac_data:
            mac_tree.insert("", "end", values=(ip, mac))

        # Tab 2: MAC Distribution Analysis
        tab2 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab2, text="MAC Distribution")
        
        # Summary stats
        total_ips = len(mac_data)
        unique_macs = len(mac_to_ips)
        avg_ips_per_mac = total_ips / unique_macs if unique_macs > 0 else 0
        
        stats_text = f"""
📊 MAC Address Distribution Analysis:

• Total IPs: {total_ips}
• Unique MACs: {unique_macs}
• Average IPs per MAC: {avg_ips_per_mac:.1f}
• Most shared MAC: {max(len(ips) for ips in mac_to_ips.values()) if mac_to_ips else 0} IPs

🔍 Common reasons for shared MACs:
• NAT (Network Address Translation)
• Load Balancers
• VPN Services
• Cloud Infrastructure
• Network Devices (Switches/Routers)
        """
        
        stats_label = tk.Label(tab2, text=stats_text, font=("Courier", 10), 
                              fg="lightgreen", bg="#1e1e2f", justify="left")
        stats_label.pack(padx=20, pady=10, anchor="w")

        # MAC distribution treeview
        dist_tree = ttk.Treeview(tab2, columns=("MAC", "IP_Count", "IPs"), show="headings", height=10)
        dist_tree.heading("MAC", text="MAC Address")
        dist_tree.heading("IP_Count", text="IP Count")
        dist_tree.heading("IPs", text="Sample IPs")
        
        dist_tree.column("MAC", width=200)
        dist_tree.column("IP_Count", width=80)
        dist_tree.column("IPs", width=300)
        
        dist_tree.pack(padx=20, pady=10, fill="both", expand=True)

        # Add distribution data
        for mac, ips in sorted(mac_to_ips.items(), key=lambda x: len(x[1]), reverse=True):
            sample_ips = ", ".join(ips[:3])  # Show first 3 IPs
            if len(ips) > 3:
                sample_ips += f" (+{len(ips)-3} more)"
            dist_tree.insert("", "end", values=(mac, len(ips), sample_ips))

        # Close button
        tk.Button(popup, text="Close", command=popup.destroy, bg="#3a3a5c", fg="white").pack(pady=10)

    def show_payload_popup(payload_data):
        popup = tk.Toplevel(app)
        popup.title("📦 Payload Inspection Results")
        popup.geometry("700x500")
        popup.configure(bg="#1e1e2f")

        # Title
        tk.Label(popup, text="📦 Payload Inspection Results", font=("Helvetica", 16, "bold"), 
                fg="white", bg="#1e1e2f").pack(pady=10)

        # Create treeview for data
        payload_tree = ttk.Treeview(popup, columns=("IP", "Payload"), show="headings", height=15)
        payload_tree.heading("IP", text="IP Address")
        payload_tree.heading("Payload", text="Payload (First 50 bytes)")
        
        # Set column widths
        payload_tree.column("IP", width=150)
        payload_tree.column("Payload", width=500)
        
        payload_tree.pack(padx=20, pady=10, fill="both", expand=True)

        # Add data to treeview
        for ip, payload in payload_data.items():
            # Handle payload data properly
            if isinstance(payload, bytes):
                payload_str = payload.hex()[:100] + "..." if len(payload.hex()) > 100 else payload.hex()
            else:
                payload_str = str(payload)[:100] + "..." if len(str(payload)) > 100 else str(payload)
            
            payload_tree.insert("", "end", values=(ip, payload_str))

        # Close button
        tk.Button(popup, text="Close", command=popup.destroy, bg="#3a3a5c", fg="white").pack(pady=10)

    def show_detailed_analysis_popup(analysis_data):
        popup = tk.Toplevel(app)
        popup.title("📊 Detailed Packet Analysis Results")
        popup.geometry("1000x800")
        popup.configure(bg="#1e1e2f")

        # Title
        tk.Label(popup, text="📊 Detailed Packet Analysis Results", font=("Helvetica", 16, "bold"), 
                fg="white", bg="#1e1e2f").pack(pady=10)

        # Create notebook for tabs
        notebook = ttk.Notebook(popup)
        notebook.pack(padx=20, pady=10, fill="both", expand=True)

        # Tab 1: Protocol Statistics
        tab1 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab1, text="Protocol Stats")
        
        protocol_text = tk.Text(tab1, bg="#2a2a3a", fg="lightgreen", font=("Courier", 10), wrap="word")
        protocol_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display protocol statistics
        protocol_text.insert("end", "📊 PROTOCOL STATISTICS\n")
        protocol_text.insert("end", "=" * 50 + "\n\n")
        protocol_text.insert("end", f"Total Packets: {analysis_data.get('total_packets', 0):,}\n")
        protocol_text.insert("end", f"Average Packet Size: {analysis_data.get('avg_packet_size', 0):.1f} bytes\n\n")
        
        protocol_text.insert("end", "🔍 Protocol Distribution:\n")
        for protocol, count in analysis_data.get('protocol_stats', {}).items():
            percentage = (count / analysis_data.get('total_packets', 1)) * 100
            protocol_text.insert("end", f"  • {protocol}: {count:,} packets ({percentage:.1f}%)\n")
        
        protocol_text.insert("end", "\n🔍 Top Ports Used:\n")
        for port_info, count in analysis_data.get('top_ports', {}).items():
            protocol_text.insert("end", f"  • {port_info}: {count:,} packets\n")

        # Tab 2: Website Access
        tab2 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab2, text="Website Access")
        
        website_text = tk.Text(tab2, bg="#2a2a3a", fg="lightblue", font=("Courier", 10), wrap="word")
        website_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display website access
        website_text.insert("end", "🌐 WEBSITE ACCESS ANALYSIS\n")
        website_text.insert("end", "=" * 50 + "\n\n")
        
        websites = analysis_data.get('top_websites', {})
        if websites:
            website_text.insert("end", "🔍 Most Accessed Websites:\n")
            for website, count in websites.items():
                website_text.insert("end", f"  • {website}: {count} queries\n")
        else:
            website_text.insert("end", "No website access detected in this capture.\n")
        
        website_text.insert("end", "\n🔍 DNS Queries:\n")
        for query in analysis_data.get('dns_queries', [])[:20]:  # Show first 20
            website_text.insert("end", f"  • {query['src_ip']} → {query['query']}\n")

        # Tab 3: Credential Detection (Passwords & Usernames)
        tab3 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab3, text="Credential Detection")
        
        password_text = tk.Text(tab3, bg="#2a2a3a", fg="red", font=("Courier", 10), wrap="word")
        password_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display potential credentials (passwords and usernames)
        password_text.insert("end", "🔐 CREDENTIAL DETECTION (PASSWORDS & USERNAMES)\n")
        password_text.insert("end", "=" * 60 + "\n\n")
        
        credentials = analysis_data.get('potential_passwords', [])
        if credentials:
            # Separate credentials by type
            passwords = [c for c in credentials if c.get('credential_type') == 'password']
            usernames = [c for c in credentials if c.get('credential_type') == 'username']
            
            password_text.insert("end", f"⚠️ Found {len(credentials)} potential credential fields!\n")
            password_text.insert("end", f"   • Passwords: {len(passwords)}\n")
            password_text.insert("end", f"   • Usernames: {len(usernames)}\n\n")
            
            # Display usernames first
            if usernames:
                password_text.insert("end", "👤 USERNAMES DETECTED:\n")
                password_text.insert("end", "-" * 30 + "\n")
                for cred in usernames:
                    password_text.insert("end", f"🔍 Field: {cred['field']}\n")
                    password_text.insert("end", f"   Source IP: {cred['src_ip']}\n")
                    password_text.insert("end", f"   Destination IP: {cred['dst_ip']}\n")
                    password_text.insert("end", f"   Value: {cred['value']}\n")
                    password_text.insert("end", "-" * 30 + "\n")
            
            # Display passwords
            if passwords:
                password_text.insert("end", "\n🔒 PASSWORDS DETECTED:\n")
                password_text.insert("end", "-" * 30 + "\n")
                for cred in passwords:
                    password_text.insert("end", f"🔍 Field: {cred['field']}\n")
                    password_text.insert("end", f"   Source IP: {cred['src_ip']}\n")
                    password_text.insert("end", f"   Destination IP: {cred['dst_ip']}\n")
                    password_text.insert("end", f"   Value: {cred['value']}\n")
                    password_text.insert("end", "-" * 30 + "\n")
        else:
            password_text.insert("end", "✅ No potential credentials detected in this capture.\n")

        # Tab 4: Suspicious Activity
        tab4 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab4, text="Suspicious Activity")
        
        suspicious_text = tk.Text(tab4, bg="#2a2a3a", fg="orange", font=("Courier", 10), wrap="word")
        suspicious_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display suspicious activity
        suspicious_text.insert("end", "🚨 SUSPICIOUS ACTIVITY DETECTION\n")
        suspicious_text.insert("end", "=" * 50 + "\n\n")
        
        suspicious = analysis_data.get('suspicious_activity', [])
        if suspicious:
            for activity in suspicious:
                color = "🔴" if activity['severity'] == 'High' else "🟡" if activity['severity'] == 'Medium' else "🟢"
                suspicious_text.insert("end", f"{color} {activity['type']} ({activity['severity']})\n")
                suspicious_text.insert("end", f"   Details: {activity['details']}\n")
                suspicious_text.insert("end", "-" * 40 + "\n")
        else:
            suspicious_text.insert("end", "✅ No suspicious activity detected.\n")

        # Tab 5: Connection Analysis
        tab5 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab5, text="Connections")
        
        connection_text = tk.Text(tab5, bg="#2a2a3a", fg="cyan", font=("Courier", 10), wrap="word")
        connection_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display connection analysis
        connection_text.insert("end", "🔗 CONNECTION ANALYSIS\n")
        connection_text.insert("end", "=" * 50 + "\n\n")
        
        connections = analysis_data.get('top_connections', {})
        if connections:
            connection_text.insert("end", "🔍 Most Frequent Connections:\n")
            for connection, count in connections.items():
                connection_text.insert("end", f"  • {connection}: {count} packets\n")
        else:
            connection_text.insert("end", "No connection data available.\n")

        # Close button
        tk.Button(popup, text="Close", command=popup.destroy, bg="#3a3a5c", fg="white").pack(pady=10)

    def show_enhanced_analysis_popup(enhanced_data):
        popup = tk.Toplevel()
        popup.title("🔐 Enhanced De-anonymization Results")
        popup.geometry("1200x900")
        popup.configure(bg="#1e1e2f")

        # Title
        tk.Label(popup, text="🔐 Enhanced De-anonymization Analysis", font=("Helvetica", 16, "bold"), 
                fg="white", bg="#1e1e2f").pack(pady=10)

        # Create notebook for tabs
        notebook = ttk.Notebook(popup)
        notebook.pack(padx=20, pady=10, fill="both", expand=True)

        # Tab 1: Real IP Detection Results
        tab1 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab1, text="🎯 Real IP Detection")
        
        real_ip_text = tk.Text(tab1, bg="#2a2a3a", fg="lightgreen", font=("Courier", 10), wrap="word")
        real_ip_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display real IP detection results
        real_ip_results = enhanced_data.get('real_ip_detection', {})
        if 'error' not in real_ip_results:
            real_ip_text.insert("end", "🎯 REAL IP DETECTION RESULTS\n")
            real_ip_text.insert("end", "=" * 50 + "\n\n")
            
            vpn_ips = real_ip_results.get('vpn_ips_detected', [])
            potential_ips = real_ip_results.get('potential_real_ips', [])
            dns_leaks = real_ip_results.get('dns_leak_ips', [])
            webrtc_leaks = real_ip_results.get('webrtc_leak_ips', [])
            timing_ips = real_ip_results.get('timing_correlation_ips', [])
            confidence_scores = real_ip_results.get('confidence_scores', {})
            
            real_ip_text.insert("end", f"🔴 VPN IPs Detected: {len(vpn_ips)}\n")
            for ip in vpn_ips:
                real_ip_text.insert("end", f"   • {ip}\n")
            
            real_ip_text.insert("end", f"\n💡 Potential Real IPs: {len(potential_ips)}\n")
            if potential_ips:
                for ip in potential_ips:
                    confidence = confidence_scores.get(ip, 0)
                    real_ip_text.insert("end", f"   🎯 {ip} (Confidence: {confidence}%)\n")
            else:
                real_ip_text.insert("end", "   ❌ No high-confidence real IPs detected\n")
            
            real_ip_text.insert("end", f"\n🌐 DNS Leak IPs: {len(dns_leaks)}\n")
            for ip in dns_leaks[:10]:  # Show first 10
                real_ip_text.insert("end", f"   🚨 {ip}\n")
            if len(dns_leaks) > 10:
                real_ip_text.insert("end", f"   ... and {len(dns_leaks) - 10} more\n")
            
            real_ip_text.insert("end", f"\n📡 WebRTC Leak IPs: {len(webrtc_leaks)}\n")
            for ip in webrtc_leaks:
                real_ip_text.insert("end", f"   🚨 {ip}\n")
            
            real_ip_text.insert("end", f"\n⏱️ Timing Correlation IPs: {len(timing_ips)}\n")
            for ip in timing_ips:
                real_ip_text.insert("end", f"   🔗 {ip}\n")
            
            # Analysis summary
            summary = real_ip_results.get('analysis_summary', {})
            if summary:
                real_ip_text.insert("end", "\n📊 Analysis Summary:\n")
                real_ip_text.insert("end", f"   • Methods Used: {summary.get('total_methods_used', 0)}\n")
                real_ip_text.insert("end", f"   • Success Rate: {summary.get('overall_success_rate', 0)}%\n")
                
                if summary.get('highest_confidence_ip'):
                    highest = summary['highest_confidence_ip']
                    real_ip_text.insert("end", f"   • Top Candidate: {highest['ip']} ({highest['confidence']}%)\n")
        else:
            real_ip_text.insert("end", f"❌ Error: {real_ip_results['error']}")

        # Tab 2: Encrypted Data Extraction
        tab2 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab2, text="🔒 Encrypted Data")
        
        encrypted_text = tk.Text(tab2, bg="#2a2a3a", fg="lightblue", font=("Courier", 10), wrap="word")
        encrypted_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display encrypted data extraction results
        encrypted_extraction = enhanced_data.get('encrypted_data_extraction', {})
        total_packets = encrypted_extraction.get('total_encrypted_packets', 0)
        sample_packets = encrypted_extraction.get('sample_packets', [])
        
        encrypted_text.insert("end", "🔒 ENCRYPTED DATA EXTRACTION\n")
        encrypted_text.insert("end", "=" * 50 + "\n\n")
        encrypted_text.insert("end", f"📊 Total VPN Encrypted Packets: {total_packets}\n\n")
        
        if sample_packets:
            encrypted_text.insert("end", "🔍 Sample Encrypted Packets:\n")
            encrypted_text.insert("end", "-" * 40 + "\n")
            
            for i, pkt in enumerate(sample_packets[:5], 1):
                direction = "OUT" if pkt['src_ip'] != "51.15.62.60" else "IN"
                encrypted_text.insert("end", f"{i}. [{direction}] {pkt['src_ip']} → {pkt['dst_ip']}\n")
                encrypted_text.insert("end", f"   Length: {pkt['data_length']} bytes\n")
                encrypted_text.insert("end", f"   Hex: {pkt['hex_data'][:60]}...\n")
                encrypted_text.insert("end", "-" * 40 + "\n")
        else:
            encrypted_text.insert("end", "❌ No encrypted packets extracted\n")

        # Tab 3: DNS Leak Analysis
        tab3 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab3, text="🌐 DNS Leaks")
        
        dns_text = tk.Text(tab3, bg="#2a2a3a", fg="orange", font=("Courier", 10), wrap="word")
        dns_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display DNS leak results
        dns_results = enhanced_data.get('dns_leaks', {})
        if 'error' not in dns_results:
            dns_text.insert("end", "🌐 DNS LEAK ANALYSIS\n")
            dns_text.insert("end", "=" * 50 + "\n\n")
            
            total_queries = dns_results.get('total_dns_queries', 0)
            leaked_queries = dns_results.get('leaked_queries', 0)
            dns_servers = dns_results.get('dns_servers_used', [])
            suspicious_domains = dns_results.get('suspicious_domains', [])
            
            # Handle case where dns_servers might be a dict instead of list
            if isinstance(dns_servers, dict):
                dns_servers_list = list(dns_servers.keys())
            else:
                dns_servers_list = dns_servers if isinstance(dns_servers, list) else []
            
            dns_text.insert("end", f"📊 Total DNS Queries: {total_queries}\n")
            dns_text.insert("end", f"🚨 Leaked Queries: {leaked_queries}\n")
            dns_text.insert("end", f"🌐 DNS Servers Used: {len(dns_servers_list)}\n\n")
            
            # DNS Servers Details
            if dns_servers_list:
                dns_text.insert("end", "🌐 DNS Servers:\n")
                for server in dns_servers_list[:10]:
                    # Get server details if available
                    server_info = dns_results.get('dns_server_analysis', {}).get(server, {})
                    server_type = server_info.get('type', 'Unknown')
                    privacy_risk = server_info.get('privacy_risk', 'Unknown')
                    dns_text.insert("end", f"   • {server} ({server_type}) - Risk: {privacy_risk}\n")
                if len(dns_servers_list) > 10:
                    dns_text.insert("end", f"   ... and {len(dns_servers_list) - 10} more servers\n")
            
            # WebRTC Leak Details
            webrtc_leaks = dns_results.get('webrtc_leaks', [])
            dns_text.insert("end", f"\n📡 WebRTC Leak IPs: {len(webrtc_leaks)}\n")
            if webrtc_leaks:
                for leak_ip in webrtc_leaks[:5]:
                    dns_text.insert("end", f"   🚨 {leak_ip}\n")
                if len(webrtc_leaks) > 5:
                    dns_text.insert("end", f"   ... and {len(webrtc_leaks) - 5} more\n")
            
            # Timing Correlation Details
            timing_ips = dns_results.get('timing_correlation_ips', [])
            dns_text.insert("end", f"\n⏱️ Timing Correlation IPs: {len(timing_ips)}\n")
            if timing_ips:
                for timing_ip in timing_ips[:5]:
                    dns_text.insert("end", f"   🔗 {timing_ip}\n")
                if len(timing_ips) > 5:
                    dns_text.insert("end", f"   ... and {len(timing_ips) - 5} more\n")
            
            # HTTP Header Leaks
            http_leaks = dns_results.get('http_header_leaks', [])
            if http_leaks:
                dns_text.insert("end", f"\n📋 HTTP Header Leaks: {len(http_leaks)}\n")
                for header_leak in http_leaks[:3]:
                    dns_text.insert("end", f"   📄 {header_leak}\n")
            
            # Privacy Assessment
            privacy_assessment = dns_results.get('privacy_assessment', {})
            if privacy_assessment:
                risk_score = privacy_assessment.get('overall_risk_score', 0)
                risk_level = privacy_assessment.get('risk_level', 'Unknown')
                dns_text.insert("end", f"\n🛡️ Privacy Risk Assessment:\n")
                dns_text.insert("end", f"   Risk Level: {risk_level} ({risk_score:.2f})\n")
                
                risk_factors = privacy_assessment.get('risk_factors', [])
                if risk_factors:
                    dns_text.insert("end", "   Risk Factors:\n")
                    # Handle both list and dict types for risk_factors
                    if isinstance(risk_factors, list):
                        for factor in risk_factors[:5]:
                            dns_text.insert("end", f"     • {factor}\n")
                    elif isinstance(risk_factors, dict):
                        for key, value in list(risk_factors.items())[:5]:
                            dns_text.insert("end", f"     • {key}: {value}\n")
                    else:
                        dns_text.insert("end", f"     • {risk_factors}\n")
            
            # Suspicious Domains
            if suspicious_domains:
                dns_text.insert("end", f"\n🚨 Suspicious Domains ({len(suspicious_domains)}):\n")
                for domain in suspicious_domains[:10]:
                    # Get suspicion reason if available
                    domain_info = dns_results.get('suspicious_domain_analysis', {}).get(domain, {})
                    reason = domain_info.get('reason', 'May reveal personal information')
                    dns_text.insert("end", f"   • {domain} - {reason}\n")
                if len(suspicious_domains) > 10:
                    dns_text.insert("end", f"   ... and {len(suspicious_domains) - 10} more\n")
            
            # Recommendations
            recommendations = dns_results.get('recommendations', [])
            if recommendations:
                dns_text.insert("end", f"\n💡 Recommendations:\n")
                for rec in recommendations[:5]:
                    dns_text.insert("end", f"   • {rec}\n")
        else:
            dns_text.insert("end", f"❌ Error: {dns_results['error']}")

        # Tab 4: Encrypted Traffic Analysis
        tab4 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab4, text="📊 Traffic Analysis")
        
        traffic_text = tk.Text(tab4, bg="#2a2a3a", fg="cyan", font=("Courier", 10), wrap="word")
        traffic_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display encrypted traffic analysis
        encrypted_results = enhanced_data.get('encrypted_traffic', {})
        if 'error' not in encrypted_results:
            traffic_text.insert("end", "📊 ENCRYPTED TRAFFIC ANALYSIS\n")
            traffic_text.insert("end", "=" * 50 + "\n\n")
            
            # Statistics Overview
            statistics = encrypted_results.get('statistics', {})
            if statistics:
                traffic_text.insert("end", "📈 ENCRYPTION STATISTICS:\n")
                traffic_text.insert("end", f"   🔒 Total Encrypted Packets: {statistics.get('total_encrypted_packets', 0)}\n")
                traffic_text.insert("end", f"   🌐 TLS/SSL Packets: {statistics.get('tls_packets', 0)}\n")
                traffic_text.insert("end", f"   🛡️ VPN Encrypted Packets: {statistics.get('vpn_packets', 0)}\n")
                traffic_text.insert("end", f"   ❓ Other Encrypted Packets: {statistics.get('raw_encrypted_packets', 0)}\n\n")
            
            # TLS Sessions Analysis
            tls_sessions = encrypted_results.get('tls_sessions', [])
            if tls_sessions:
                traffic_text.insert("end", f"🔐 TLS/SSL SESSIONS ({len(tls_sessions)}):\n")
                for i, session in enumerate(tls_sessions[:5]):
                    traffic_text.insert("end", f"   Session {i+1}: {session.get('src_ip', 'Unknown')}:{session.get('src_port', 0)} → {session.get('dst_ip', 'Unknown')}:{session.get('dst_port', 0)}\n")
                    traffic_text.insert("end", f"      📦 Length: {session.get('data_length', 0)} bytes\n")
                    traffic_text.insert("end", f"      🛡️ VPN Related: {'✅' if session.get('is_vpn_related', False) else '❌'}\n")
                    traffic_text.insert("end", f"      🔢 Hex Preview: {session.get('encrypted_payload', '')[:32]}...\n")
                    traffic_text.insert("end", f"      📊 Protocol: {session.get('protocol', 'Unknown')}\n\n")
                if len(tls_sessions) > 5:
                    traffic_text.insert("end", f"   ... and {len(tls_sessions) - 5} more TLS sessions\n\n")
            
            # VPN Encrypted Data Analysis
            vpn_data = encrypted_results.get('vpn_encrypted_data', [])
            if vpn_data:
                traffic_text.insert("end", f"🛡️ VPN ENCRYPTED DATA ({len(vpn_data)}):\n")
                for i, vpn_packet in enumerate(vpn_data[:3]):
                    traffic_text.insert("end", f"   VPN Packet {i+1}: {vpn_packet.get('src_ip', 'Unknown')}:{vpn_packet.get('src_port', 0)} → {vpn_packet.get('dst_ip', 'Unknown')}:{vpn_packet.get('dst_port', 0)}\n")
                    traffic_text.insert("end", f"      📦 Length: {vpn_packet.get('data_length', 0)} bytes\n")
                    traffic_text.insert("end", f"      🔐 Encryption Type: {vpn_packet.get('encryption_type', 'Unknown')}\n")
                    traffic_text.insert("end", f"      🔢 Hex Data: {vpn_packet.get('encrypted_payload', '')[:64]}...\n")
                    traffic_text.insert("end", f"      📊 Protocol: {vpn_packet.get('protocol', 'Unknown')}\n\n")
                if len(vpn_data) > 3:
                    traffic_text.insert("end", f"   ... and {len(vpn_data) - 3} more VPN packets\n\n")
            
            # Other Encrypted Payloads
            encrypted_payloads = encrypted_results.get('encrypted_payloads', [])
            if encrypted_payloads:
                traffic_text.insert("end", f"❓ OTHER ENCRYPTED PAYLOADS ({len(encrypted_payloads)}):\n")
                for i, payload in enumerate(encrypted_payloads[:3]):
                    traffic_text.insert("end", f"   Payload {i+1}: {payload.get('src_ip', 'Unknown')} → {payload.get('dst_ip', 'Unknown')}\n")
                    traffic_text.insert("end", f"      📦 Length: {payload.get('data_length', 0)} bytes\n")
                    traffic_text.insert("end", f"      📊 Entropy Score: {payload.get('entropy_score', 0):.2f}\n")
                    traffic_text.insert("end", f"      🔢 Hex Sample: {payload.get('encrypted_payload', '')[:32]}...\n")
                    traffic_text.insert("end", f"      📊 Protocol: {payload.get('protocol', 'Unknown')}\n\n")
                if len(encrypted_payloads) > 3:
                    traffic_text.insert("end", f"   ... and {len(encrypted_payloads) - 3} more encrypted payloads\n\n")
            
            # Binary Analysis Summary
            analyzed_ips = encrypted_results.get('analyzed_ips', [])
            traffic_patterns = encrypted_results.get('traffic_patterns', {})
            applications = encrypted_results.get('detected_applications', [])
            
            if analyzed_ips:
                traffic_text.insert("end", f"🔍 ANALYZED IPs ({len(analyzed_ips)}):\n")
                for ip in analyzed_ips[:10]:
                    traffic_text.insert("end", f"   • {ip}\n")
                if len(analyzed_ips) > 10:
                    traffic_text.insert("end", f"   ... and {len(analyzed_ips) - 10} more IPs\n")
                traffic_text.insert("end", "\n")
            
            if traffic_patterns:
                traffic_text.insert("end", f"📈 TRAFFIC PATTERNS:\n")
                for pattern, count in traffic_patterns.items():
                    traffic_text.insert("end", f"   • {pattern}: {count}\n")
                traffic_text.insert("end", "\n")
            
            if applications:
                traffic_text.insert("end", f"📱 DETECTED APPLICATIONS:\n")
                for app in applications:
                    traffic_text.insert("end", f"   • {app}\n")
                traffic_text.insert("end", "\n")
            
            # Encryption Quality Assessment
            traffic_text.insert("end", "🔬 BINARY ANALYSIS INSIGHTS:\n")
            traffic_text.insert("end", "   • High entropy data indicates strong encryption\n")
            traffic_text.insert("end", "   • TLS sessions show application-layer encryption\n")
            traffic_text.insert("end", "   • VPN tunnels provide network-layer encryption\n")
            traffic_text.insert("end", "   • Hex dumps reveal encryption signatures and patterns\n")
        else:
            traffic_text.insert("end", f"❌ Error: {encrypted_results['error']}")

        # Tab 5: Advanced Fingerprinting
        tab5 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab5, text="🔬 Fingerprinting")
        
        fingerprint_text = tk.Text(tab5, bg="#2a2a3a", fg="lightgreen", font=("Courier", 10), wrap="word")
        fingerprint_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display advanced fingerprinting results
        fingerprint_results = enhanced_data.get('advanced_fingerprints', {})
        if 'error' not in fingerprint_results:
            fingerprint_text.insert("end", "🔬 ADVANCED DEVICE FINGERPRINTING\n")
            fingerprint_text.insert("end", "=" * 50 + "\n\n")
            
            # OS Detection
            os_detection = fingerprint_results.get('os_detection', {})
            if os_detection:
                fingerprint_text.insert("end", "💻 OPERATING SYSTEM DETECTION:\n")
                for ip, os_info in os_detection.items():
                    fingerprint_text.insert("end", f"   📱 {ip}:\n")
                    fingerprint_text.insert("end", f"      OS: {os_info.get('os', 'Unknown')}\n")
                    fingerprint_text.insert("end", f"      Version: {os_info.get('version', 'Unknown')}\n")
                    fingerprint_text.insert("end", f"      TTL: {os_info.get('ttl', 'Unknown')}\n")
                    fingerprint_text.insert("end", f"      Confidence: {os_info.get('confidence', 0)}%\n\n")
            
            # Device Fingerprints
            device_fingerprints = fingerprint_results.get('device_fingerprints', {})
            if device_fingerprints:
                fingerprint_text.insert("end", "🖥️ DEVICE FINGERPRINTS:\n")
                for ip, device_info in device_fingerprints.items():
                    fingerprint_text.insert("end", f"   🔍 {ip}:\n")
                    fingerprint_text.insert("end", f"      Device Type: {device_info.get('device_type', 'Unknown')}\n")
                    fingerprint_text.insert("end", f"      Browser: {device_info.get('browser', 'Unknown')}\n")
                    fingerprint_text.insert("end", f"      Platform: {device_info.get('platform', 'Unknown')}\n")
                    fingerprint_text.insert("end", f"      MAC Vendor: {device_info.get('mac_vendor', 'Unknown')}\n\n")
            
            # Network Behavior
            network_behavior = fingerprint_results.get('network_behavior', {})
            if network_behavior:
                fingerprint_text.insert("end", "🌐 NETWORK BEHAVIOR ANALYSIS:\n")
                for ip, behavior in network_behavior.items():
                    fingerprint_text.insert("end", f"   📊 {ip}:\n")
                    fingerprint_text.insert("end", f"      Connection Pattern: {behavior.get('connection_pattern', 'Unknown')}\n")
                    fingerprint_text.insert("end", f"      Traffic Volume: {behavior.get('traffic_volume', 'Unknown')}\n")
                    fingerprint_text.insert("end", f"      Protocol Usage: {behavior.get('protocol_usage', 'Unknown')}\n")
                    fingerprint_text.insert("end", f"      Timing Pattern: {behavior.get('timing_pattern', 'Unknown')}\n\n")
            
            # Application Signatures
            app_signatures = fingerprint_results.get('application_signatures', {})
            if app_signatures:
                fingerprint_text.insert("end", "📱 APPLICATION SIGNATURES:\n")
                for ip, apps in app_signatures.items():
                    fingerprint_text.insert("end", f"   🔍 {ip}:\n")
                    if isinstance(apps, list):
                        for app in apps[:5]:
                            fingerprint_text.insert("end", f"      • {app}\n")
                    else:
                        fingerprint_text.insert("end", f"      • {apps}\n")
                    fingerprint_text.insert("end", "\n")
        else:
            fingerprint_text.insert("end", f"❌ Error: {fingerprint_results['error']}")

        # Tab 6: Traffic Flow Analysis
        tab6 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab6, text="🔗 Flow Analysis")
        
        flow_text = tk.Text(tab6, bg="#2a2a3a", fg="yellow", font=("Courier", 10), wrap="word")
        flow_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display traffic flow analysis results
        flow_results = enhanced_data.get('traffic_flows', {})
        if 'error' not in flow_results:
            flow_text.insert("end", "🔗 TRAFFIC FLOW CORRELATION\n")
            flow_text.insert("end", "=" * 50 + "\n\n")
            
            # Flow Statistics
            flow_stats = flow_results.get('flow_statistics', {})
            if flow_stats:
                flow_text.insert("end", "📊 FLOW STATISTICS:\n")
                flow_text.insert("end", f"   Total Flows: {flow_stats.get('total_flows', 0)}\n")
                flow_text.insert("end", f"   Unique IPs: {flow_stats.get('unique_ips', 0)}\n")
                flow_text.insert("end", f"   Average Flow Duration: {flow_stats.get('avg_duration', 0):.2f}s\n")
                flow_text.insert("end", f"   Total Data Volume: {flow_stats.get('total_volume', 0)} bytes\n\n")
            
            # Correlation Results
            correlations = flow_results.get('correlations', {})
            if correlations:
                flow_text.insert("end", "🔗 CORRELATION ANALYSIS:\n")
                for correlation_type, data in correlations.items():
                    flow_text.insert("end", f"   {correlation_type.upper()}:\n")
                    if isinstance(data, dict):
                        for key, value in data.items():
                            flow_text.insert("end", f"      {key}: {value}\n")
                    elif isinstance(data, list):
                        for item in data[:5]:
                            flow_text.insert("end", f"      • {item}\n")
                    flow_text.insert("end", "\n")
            
            # Suspicious Patterns
            suspicious_patterns = flow_results.get('suspicious_patterns', [])
            if suspicious_patterns:
                flow_text.insert("end", f"🚨 SUSPICIOUS PATTERNS ({len(suspicious_patterns)}):\n")
                for i, pattern in enumerate(suspicious_patterns[:5]):
                    flow_text.insert("end", f"   {i+1}. {pattern.get('description', 'Unknown pattern')}\n")
                    flow_text.insert("end", f"      Severity: {pattern.get('severity', 'Unknown')}\n")
                    flow_text.insert("end", f"      IPs Involved: {', '.join(pattern.get('ips', []))}\n\n")
            
            # Flow Timing Analysis
            timing_analysis = flow_results.get('timing_analysis', {})
            if timing_analysis:
                flow_text.insert("end", "⏱️ TIMING ANALYSIS:\n")
                flow_text.insert("end", f"   Peak Traffic Time: {timing_analysis.get('peak_time', 'Unknown')}\n")
                flow_text.insert("end", f"   Traffic Patterns: {timing_analysis.get('patterns', 'Unknown')}\n")
                flow_text.insert("end", f"   Correlation Score: {timing_analysis.get('correlation_score', 0):.2f}\n\n")
        else:
            flow_text.insert("end", f"❌ Error: {flow_results['error']}")

        # Close button
        tk.Button(popup, text="Close", command=popup.destroy, bg="#3a3a5c", fg="white").pack(pady=10)

    # === GUI Init ===
    app = tk.Tk()
    app.title("🛡️ VPN Detection & De-anonymization")
    app.geometry("960x780")
    app.configure(bg="#1e1e2f")

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background="#1e1e2f", foreground="white", fieldbackground="#1e1e2f")
    style.map("Treeview", background=[("selected", "#29293d")])

    tk.Label(app, text="VPN Detection Framework", font=("Helvetica", 18, "bold"), fg="white", bg="#1e1e2f").pack(pady=10)

    tk.Button(app, text="📂 Select PCAP/PCAPNG File", command=select_file, bg="#3a3a5c", fg="white").pack(pady=5)
    file_label = tk.Label(app, text="No file selected", fg="gray", bg="#1e1e2f")
    file_label.pack()

    tk.Button(app, text="🔍 Start VPN Analysis", command=analyze_file, bg="#3a3a5c", fg="white").pack(pady=10)

    tree = ttk.Treeview(app, columns=("IP", "VPN"), show="headings", height=10)
    tree.heading("IP", text="IP Address")
    tree.heading("VPN", text="VPN Detected")
    tree.pack(padx=20, pady=10, fill="x")

    progress_label = tk.Label(app, text="", fg="lightgreen", bg="#1e1e2f", font=("Courier", 10))
    progress_label.pack()

    btn_frame = tk.Frame(app, bg="#1e1e2f")
    btn_frame.pack(pady=6)

    tk.Button(btn_frame, text="📊 Show VPN Charts", command=lambda: show_chart_popup(app.results), bg="#3a3a5c", fg="white").grid(row=0, column=0, padx=5)
    tk.Button(btn_frame, text="💾 Export Report", command=save_to_csv, bg="#3a3a5c", fg="white").grid(row=0, column=1, padx=5)
    tk.Button(btn_frame, text="🧠 De-anonymize VPN IPs", command=run_deanonymization, bg="#3a3a5c", fg="white").grid(row=0, column=2, padx=5)
    tk.Button(btn_frame, text="⚙️ Advanced Analysis", command=open_advanced_analysis, bg="#3a3a5c", fg="white").grid(row=0, column=3, padx=5)
    tk.Button(btn_frame, text="📁 Export Full Report", command=save_full_csv, bg="#3a3a5c", fg="white").grid(row=0, column=4, padx=5)
    tk.Button(btn_frame, text="📊 Export Excel Report", command=save_comprehensive_excel, bg="#4CAF50", fg="white").grid(row=0, column=5, padx=5)

    tk.Label(app, text="De-anonymization Results", fg="white", bg="#1e1e2f", font=("Helvetica", 14)).pack(pady=(20, 5))
    deanonym_tree = ttk.Treeview(app, columns=("IP", "Fingerprint"), show="headings", height=8)
    deanonym_tree.heading("IP", text="IP Address")
    deanonym_tree.heading("Fingerprint", text="Fingerprint Info")
    deanonym_tree.pack(padx=20, pady=5, fill="both")

    chart_frame = tk.Frame(app, bg="#1e1e2f")
    chart_frame.pack()

    app.mainloop()
