import tkinter as tk
from tkinter import filedialog, messagebox
from utils.report_writer import save_full_report

def run_test():
    # Dummy test data
    vpn_results = [
        ("192.168.1.10", True),
        ("8.8.8.8", False),
        ("10.0.0.1", "Error")
    ]

    deanonym_results = [
        ("192.168.1.10", "Tor Exit Node"),
        ("10.0.0.1", "Suspicious Proxy")
    ]

    geo_data = {
        "192.168.1.10": {"country": "India", "city": "Hyderabad", "isp": "ACT Fibernet"},
        "8.8.8.8": {"country": "USA", "city": "Mountain View", "isp": "Google LLC"}
    }

    mac_data = {
        "192.168.1.10": "00:1A:2B:3C:4D:5E",
        "8.8.8.8": "66:77:88:99:AA:BB"
    }

    payload_data = {
        "192.168.1.10": "TLS handshake with suspicious certificate",
        "8.8.8.8": "DNS query for google.com"
    }

    total_packets = 150
    timestamp = "2025-08-06 16:30:00"

    # Tkinter root for file dialog
    root = tk.Tk()
    root.withdraw()

    file_path = filedialog.asksaveasfilename(
        title="Save Test Full Report",
        defaultextension=".csv",
        filetypes=[("CSV Files", "*.csv")]
    )

    if not file_path:
        messagebox.showwarning("Cancelled", "Save operation cancelled.")
        return

    try:
        save_full_report(
            filename=file_path,
            vpn_results=vpn_results,
            total_packets=total_packets,
            timestamp=timestamp,
            deanonym_results=deanonym_results,
            geo_data=geo_data,
            mac_data=mac_data,
            payload_data=payload_data
        )
        messagebox.showinfo("Success", f"Test full report saved to:\n{file_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    run_test()
