import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from core.packet_processor import extract_ips_from_pcap, analyze_packet_details
from core.vpn_checker import check_vpn_status
from utils.report_writer import save_report, save_full_report, save_comprehensive_excel_report
from deanon.fingerprint_extractor import extract_fingerprints
from deanon.deanonymizer import classify_fingerprint
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
                packet_analysis=packet_analysis
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

        def run_ai_analysis(ai_analyzer):
            popup.destroy()
            progress_label.config(text="🤖 Running AI Threat Analysis...")
            
            def worker():
                try:
                    # Check if we have analysis data
                    if not hasattr(app, "full_analysis") or not app.full_analysis:
                        app.after(0, lambda: progress_label.config(text="❌ No analysis data available. Run other analyses first."))
                        return
                    
                    # Get payload data if available
                    payload_data = {}
                    for ip, data in app.full_analysis.items():
                        if "Payload" in data:
                            payload_data[ip] = data["Payload"]
                    
                    # Run AI analysis
                    app.after(0, lambda: progress_label.config(text="🤖 Analyzing network behavior with AI..."))
                    network_analysis = ai_analyzer.analyze_network_behavior(app.full_analysis)
                    
                    app.after(0, lambda: progress_label.config(text="🤖 Analyzing payload intelligence..."))
                    payload_analysis = ai_analyzer.analyze_payload_intelligence(payload_data)
                    
                    app.after(0, lambda: progress_label.config(text="🤖 Generating comprehensive threat report..."))
                    threat_report = ai_analyzer.generate_threat_report(app.full_analysis, payload_data)
                    
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
        
        # Add AI Analysis button if API key is available
        ai_analyzer = get_ai_analyzer()
        if ai_analyzer:
            tk.Button(popup, text="🤖 AI Threat Analysis", command=lambda: run_ai_analysis(ai_analyzer), 
                     bg="#ff6b35", fg="white", width=25).pack(pady=10)

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

        # Tab 2: Payload Intelligence
        tab2 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab2, text="Payload Intelligence")
        
        payload_text = tk.Text(tab2, bg="#2a2a3a", fg="lightblue", font=("Courier", 10), wrap="word")
        payload_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display payload analysis
        if "error" not in payload_analysis:
            payload_text.insert("end", "🔍 PAYLOAD INTELLIGENCE ANALYSIS\n")
            payload_text.insert("end", "=" * 50 + "\n\n")
            for key, value in payload_analysis.items():
                payload_text.insert("end", f"📊 {key.replace('_', ' ').title()}:\n")
                if isinstance(value, list):
                    for item in value:
                        payload_text.insert("end", f"  • {item}\n")
                else:
                    payload_text.insert("end", f"  {value}\n")
                payload_text.insert("end", "\n")
        else:
            payload_text.insert("end", f"❌ Error: {payload_analysis['error']}")

        # Tab 3: Comprehensive Threat Report
        tab3 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab3, text="Threat Report")
        
        report_text = tk.Text(tab3, bg="#2a2a3a", fg="white", font=("Courier", 10), wrap="word")
        report_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display threat report
        report_text.insert("end", "📋 COMPREHENSIVE THREAT REPORT\n")
        report_text.insert("end", "=" * 50 + "\n\n")
        report_text.insert("end", threat_report)

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

        # Tab 3: Potential Passwords
        tab3 = tk.Frame(notebook, bg="#1e1e2f")
        notebook.add(tab3, text="Password Detection")
        
        password_text = tk.Text(tab3, bg="#2a2a3a", fg="red", font=("Courier", 10), wrap="word")
        password_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Display potential passwords
        password_text.insert("end", "🔐 POTENTIAL PASSWORD DETECTION\n")
        password_text.insert("end", "=" * 50 + "\n\n")
        
        passwords = analysis_data.get('potential_passwords', [])
        if passwords:
            password_text.insert("end", f"⚠️ Found {len(passwords)} potential password fields!\n\n")
            for pwd in passwords:
                password_text.insert("end", f"🔍 Type: {pwd['type']}\n")
                password_text.insert("end", f"   Source IP: {pwd['src_ip']}\n")
                password_text.insert("end", f"   Destination IP: {pwd['dst_ip']}\n")
                password_text.insert("end", f"   Field: {pwd['field']}\n")
                password_text.insert("end", f"   Value: {pwd['value']}\n")
                password_text.insert("end", "-" * 40 + "\n")
        else:
            password_text.insert("end", "✅ No potential passwords detected in this capture.\n")

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
