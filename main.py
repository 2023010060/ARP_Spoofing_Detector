import csv
import ipaddress
import os
import platform
import re
import socket
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    import psutil
except ImportError:
    psutil = None

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

APP_TITLE = "ARP Shield — ARP Spoofing Detection & Network Monitor"


def run_command(command):
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        )
        return result.stdout + result.stderr
    except Exception as e:
        return str(e)


def get_ipconfig_text():
    if os.name == "nt":
        return run_command(["ipconfig", "/all"])
    return run_command(["ip", "addr"])


def get_default_gateway():
    if os.name == "nt":
        text = get_ipconfig_text()
        # Prefer IPv4 Default Gateway lines.
        for line in text.splitlines():
            if "Default Gateway" in line:
                value = line.split(":", 1)[-1].strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
                    return value
        return ""
    text = run_command(["ip", "route"])
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", text)
    return m.group(1) if m else ""


def get_local_ipv4():
    try:
        if psutil:
            for name, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if getattr(a, "family", None) == socket.AF_INET and not a.address.startswith("127."):
                        return a.address
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return ""


def get_arp_table():
    """Return list of dicts: ip, mac, interface, raw."""
    output = run_command(["arp", "-a"])
    entries = []
    current_interface = ""
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Windows interface line: Interface: 192.168.1.5 --- 0x8
        m_if = re.match(r"Interface:\s+(\d+\.\d+\.\d+\.\d+)", line, re.I)
        if m_if:
            current_interface = m_if.group(1)
            continue

        # Windows: 192.168.1.1    aa-bb-cc-dd-ee-ff    dynamic
        m_win = re.match(
            r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{11,17})\s+(\w+)",
            line
        )
        if m_win:
            entries.append({
                "ip": m_win.group(1),
                "mac": m_win.group(2).replace("-", ":").lower(),
                "interface": current_interface,
                "type": m_win.group(3),
                "raw": line
            })
            continue

        # Linux/macOS style fallback: 192.168.1.1 dev wlan0 lladdr aa:bb...
        m_linux = re.search(
            r"(\d+\.\d+\.\d+\.\d+).*?(?:lladdr\s+)?([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})",
            line
        )
        if m_linux:
            entries.append({
                "ip": m_linux.group(1),
                "mac": m_linux.group(2).lower(),
                "interface": current_interface,
                "type": "dynamic",
                "raw": line
            })
    return entries


def normalize_mac(mac):
    return mac.replace("-", ":").lower()


def detect_anomalies(entries, previous_map, gateway_ip):
    """Defensive detection only. No credential/payload capture."""
    alerts = []

    # Same IP changing MAC is a classic ARP spoofing indicator.
    for e in entries:
        ip, mac = e["ip"], normalize_mac(e["mac"])
        old = previous_map.get(ip)
        if old and normalize_mac(old) != mac:
            alerts.append({
                "severity": "HIGH",
                "ip": ip,
                "mac": mac,
                "reason": f"MAC changed for {ip}: {old} → {mac}"
            })

    # Multiple IPs associated with one MAC is not automatically malicious,
    # but can be useful evidence when combined with other signals.
    mac_to_ips = defaultdict(list)
    for e in entries:
        mac_to_ips[normalize_mac(e["mac"])].append(e["ip"])
    for mac, ips in mac_to_ips.items():
        if len(ips) >= 3:
            alerts.append({
                "severity": "MEDIUM",
                "ip": ", ".join(ips[:5]),
                "mac": mac,
                "reason": "One MAC is associated with multiple IP addresses"
            })

    # Gateway mapping change gets special attention.
    if gateway_ip:
        gw = next((e for e in entries if e["ip"] == gateway_ip), None)
        if gw:
            old_gw = previous_map.get(gateway_ip)
            if old_gw and normalize_mac(old_gw) != normalize_mac(gw["mac"]):
                alerts.append({
                    "severity": "CRITICAL",
                    "ip": gateway_ip,
                    "mac": normalize_mac(gw["mac"]),
                    "reason": "Default gateway MAC changed — possible ARP spoofing"
                })

    return alerts


class ARPShieldApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1180x760")
        self.root.minsize(980, 650)

        self.running = False
        self.stop_event = threading.Event()
        self.scan_thread = None

        self.previous_map = {}
        self.current_entries = []
        self.alert_history = []
        self.scan_count = 0
        self.last_scan_time = None

        self.gateway_var = tk.StringVar(value="Detecting...")
        self.local_ip_var = tk.StringVar(value="Detecting...")
        self.status_var = tk.StringVar(value="Ready")
        self.scan_interval_var = tk.IntVar(value=5)

        self.build_style()
        self.build_ui()
        self.refresh_system_info()

    def build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"))
        style.configure("Sub.TLabel", font=("Segoe UI", 10))
        style.configure("Card.TLabelframe", padding=10)
        style.configure("Treeview", rowheight=28, font=("Consolas", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=8)

    def build_ui(self):
        top = ttk.Frame(self.root, padding=(18, 14))
        top.pack(fill="x")

        title_box = ttk.Frame(top)
        title_box.pack(side="left", fill="x", expand=True)
        ttk.Label(title_box, text="ARP Shield", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            title_box,
            text="ARP Spoofing Detection • ARP Table Monitoring • Safe Network Metadata Monitoring",
            style="Sub.TLabel"
        ).pack(anchor="w", pady=(3, 0))

        self.status_badge = tk.Label(
            top, text="● READY", font=("Segoe UI", 11, "bold"),
            padx=14, pady=8, bg="#e7f5e9", fg="#1b5e20"
        )
        self.status_badge.pack(side="right")

        info = ttk.Frame(self.root, padding=(18, 0))
        info.pack(fill="x")

        self.make_card(info, "LOCAL IPv4", self.local_ip_var, 0)
        self.make_card(info, "DEFAULT GATEWAY", self.gateway_var, 1)
        self.make_card(info, "SCAN COUNT", tk.StringVar(value="0"), 2)
        self.scan_count_var = info.grid_slaves(row=0, column=2)[0].grid_info()  # placeholder

        # Rebind count variable cleanly.
        self.scan_count_label_var = tk.StringVar(value="0")
        # Replace the third card value.
        for w in info.grid_slaves(row=0, column=2):
            w.destroy()
        card = ttk.LabelFrame(info, text="SCAN COUNT", style="Card.TLabelframe")
        card.grid(row=0, column=2, sticky="ew", padx=5)
        ttk.Label(card, textvariable=self.scan_count_label_var, font=("Segoe UI", 18, "bold")).pack(anchor="w")
        info.columnconfigure(0, weight=1)
        info.columnconfigure(1, weight=1)
        info.columnconfigure(2, weight=1)

        controls = ttk.Frame(self.root, padding=(18, 14, 18, 8))
        controls.pack(fill="x")

        ttk.Button(controls, text="▶ Start Monitoring", style="Primary.TButton",
                   command=self.start_monitoring).pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="■ Stop", command=self.stop_monitoring).pack(side="left", padx=4)
        ttk.Button(controls, text="↻ Scan Now", command=self.scan_now).pack(side="left", padx=4)
        ttk.Button(controls, text="Export CSV", command=self.export_csv).pack(side="left", padx=4)
        ttk.Button(controls, text="Generate PDF Report", command=self.generate_pdf).pack(side="left", padx=4)

        ttk.Label(controls, text="Interval (sec):").pack(side="left", padx=(20, 5))
        ttk.Spinbox(controls, from_=2, to=300, width=6, textvariable=self.scan_interval_var).pack(side="left")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=18, pady=(4, 18))

        self.arp_tab = ttk.Frame(self.notebook, padding=10)
        self.alert_tab = ttk.Frame(self.notebook, padding=10)
        self.log_tab = ttk.Frame(self.notebook, padding=10)

        self.notebook.add(self.arp_tab, text="ARP Table")
        self.notebook.add(self.alert_tab, text="Security Alerts")
        self.notebook.add(self.log_tab, text="Activity Log")

        self.build_arp_tab()
        self.build_alert_tab()
        self.build_log_tab()

    def make_card(self, parent, title, variable, col):
        card = ttk.LabelFrame(parent, text=title, style="Card.TLabelframe")
        card.grid(row=0, column=col, sticky="ew", padx=5)
        ttk.Label(card, textvariable=variable, font=("Segoe UI", 18, "bold")).pack(anchor="w")

    def build_arp_tab(self):
        cols = ("ip", "mac", "interface", "type", "status")
        self.arp_tree = ttk.Treeview(self.arp_tab, columns=cols, show="headings")
        headings = {
            "ip": "IP Address", "mac": "MAC Address", "interface": "Interface",
            "type": "Type", "status": "Status"
        }
        widths = {"ip": 180, "mac": 220, "interface": 150, "type": 110, "status": 250}
        for c in cols:
            self.arp_tree.heading(c, text=headings[c])
            self.arp_tree.column(c, width=widths[c], anchor="w")
        self.arp_tree.tag_configure("alert", background="#ffe0e0")
        self.arp_tree.pack(fill="both", expand=True)

    def build_alert_tab(self):
        cols = ("time", "severity", "ip", "mac", "reason")
        self.alert_tree = ttk.Treeview(self.alert_tab, columns=cols, show="headings")
        headings = {
            "time": "Time", "severity": "Severity", "ip": "IP",
            "mac": "MAC", "reason": "Detection Reason"
        }
        widths = {"time": 150, "severity": 100, "ip": 160, "mac": 210, "reason": 500}
        for c in cols:
            self.alert_tree.heading(c, text=headings[c])
            self.alert_tree.column(c, width=widths[c], anchor="w")
        self.alert_tree.tag_configure("critical", background="#ffb3b3")
        self.alert_tree.tag_configure("high", background="#ffd6a5")
        self.alert_tree.tag_configure("medium", background="#fff3b0")
        self.alert_tree.pack(fill="both", expand=True)

    def build_log_tab(self):
        self.log_text = tk.Text(self.log_tab, wrap="word", font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True)

    def log(self, msg):
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.root.after(0, lambda: (
            self.log_text.insert("end", f"[{stamp}] {msg}\n"),
            self.log_text.see("end")
        ))

    def refresh_system_info(self):
        self.local_ip_var.set(get_local_ipv4() or "Unknown")
        self.gateway_var.set(get_default_gateway() or "Not found")
        self.log("System information loaded.")

    def start_monitoring(self):
        if self.running:
            return
        self.running = True
        self.stop_event.clear()
        self.status_var.set("Monitoring")
        self.status_badge.config(text="● MONITORING", bg="#e3f2fd", fg="#0d47a1")
        self.log("Continuous ARP monitoring started.")
        self.scan_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.scan_thread.start()

    def stop_monitoring(self):
        self.running = False
        self.stop_event.set()
        self.status_var.set("Stopped")
        self.status_badge.config(text="● STOPPED", bg="#eeeeee", fg="#424242")
        self.log("Monitoring stopped.")

    def monitor_loop(self):
        while not self.stop_event.is_set():
            self.perform_scan()
            try:
                interval = max(2, int(self.scan_interval_var.get()))
            except Exception:
                interval = 5
            self.stop_event.wait(interval)

    def scan_now(self):
        threading.Thread(target=self.perform_scan, daemon=True).start()

    def perform_scan(self):
        entries = get_arp_table()
        gateway = get_default_gateway()
        alerts = detect_anomalies(entries, self.previous_map, gateway)

        self.current_entries = entries
        self.scan_count += 1
        self.last_scan_time = datetime.now()

        # First scan creates the baseline and should not generate false positives.
        if not self.previous_map:
            self.previous_map = {e["ip"]: e["mac"] for e in entries}
            alerts = []
            baseline_msg = f"Baseline created with {len(entries)} ARP entries."
        else:
            baseline_msg = f"Scan completed: {len(entries)} ARP entries."

        self.previous_map.update({e["ip"]: e["mac"] for e in entries})

        for alert in alerts:
            alert["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.alert_history.append(alert)

        self.root.after(0, self.update_tables, entries, alerts)
        self.log(baseline_msg)
        for a in alerts:
            self.log(f"{a['severity']} ALERT: {a['reason']} | {a['ip']} | {a['mac']}")

    def update_tables(self, entries, new_alerts):
        self.gateway_var.set(get_default_gateway() or "Not found")
        self.scan_count_label_var.set(str(self.scan_count))

        for item in self.arp_tree.get_children():
            self.arp_tree.delete(item)

        changed_ips = {a["ip"] for a in new_alerts}
        for e in entries:
            status = "⚠ Possible anomaly" if e["ip"] in changed_ips else "Normal"
            tag = "alert" if e["ip"] in changed_ips else ""
            self.arp_tree.insert(
                "", "end",
                values=(e["ip"], e["mac"], e["interface"], e["type"], status),
                tags=(tag,)
            )

        for a in new_alerts:
            sev = a["severity"].lower()
            tag = sev if sev in ("critical", "high", "medium") else ""
            self.alert_tree.insert(
                "", "end",
                values=(a["time"], a["severity"], a["ip"], a["mac"], a["reason"]),
                tags=(tag,)
            )

        if new_alerts:
            self.status_badge.config(text="● THREAT DETECTED", bg="#ffebee", fg="#b71c1c")
        elif self.running:
            self.status_badge.config(text="● PROTECTED", bg="#e8f5e9", fg="#1b5e20")

    def export_csv(self):
        if not self.current_entries:
            messagebox.showinfo("Export", "Run a scan first.")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="arp_scan_report.csv"
        )
        if not filename:
            return
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["ip", "mac", "interface", "type"]
            )
            writer.writeheader()
            writer.writerows(self.current_entries)
        messagebox.showinfo("Export", f"CSV saved to:\n{filename}")

    def generate_pdf(self):
        if not REPORTLAB_OK:
            messagebox.showerror(
                "Missing package",
                "ReportLab is not installed. Run:\npython -m pip install reportlab"
            )
            return
        if not self.current_entries:
            messagebox.showinfo("PDF Report", "Run a scan first.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            initialfile="ARP_Spoofing_Security_Report.pdf"
        )
        if not filename:
            return

        doc = SimpleDocTemplate(filename, pagesize=A4, rightMargin=30, leftMargin=30)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CustomTitle", parent=styles["Title"], alignment=TA_CENTER,
            fontSize=20, spaceAfter=12
        )
        story = [
            Paragraph("ARP Spoofing Detection & Network Monitoring Report", title_style),
            Paragraph(
                f"<b>Generated:</b> {datetime.now():%d-%m-%Y %H:%M:%S}<br/>"
                f"<b>Local IPv4:</b> {self.local_ip_var.get()}<br/>"
                f"<b>Default Gateway:</b> {self.gateway_var.get()}<br/>"
                f"<b>Total Scans:</b> {self.scan_count}<br/>"
                f"<b>Alerts Recorded:</b> {len(self.alert_history)}",
                styles["BodyText"]
            ),
            Spacer(1, 14),
            Paragraph("1. ARP Table Snapshot", styles["Heading2"])
        ]

        data = [["IP Address", "MAC Address", "Interface", "Type"]]
        data += [[e["ip"], e["mac"], e["interface"], e["type"]] for e in self.current_entries]
        table = Table(data, repeatRows=1, colWidths=[105, 135, 105, 65])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#263238")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("GRID", (0,0), (-1,-1), 0.4, colors.grey),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 7.5),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
        ]))
        story += [table, Spacer(1, 14), Paragraph("2. Security Alerts", styles["Heading2"])]

        if self.alert_history:
            adata = [["Time", "Severity", "IP", "MAC", "Reason"]]
            adata += [
                [a["time"], a["severity"], a["ip"], a["mac"], a["reason"]]
                for a in self.alert_history[-30:]
            ]
            atable = Table(adata, repeatRows=1, colWidths=[80, 55, 75, 105, 190])
            atable.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#6d1b1b")),
                ("TEXTCOLOR", (0,0), (-1,0), colors.white),
                ("GRID", (0,0), (-1,-1), 0.4, colors.grey),
                ("FONTSIZE", (0,0), (-1,-1), 6.5),
                ("VALIGN", (0,0), (-1,-1), "TOP"),
            ]))
            story.append(atable)
        else:
            story.append(Paragraph(
                "No ARP anomalies were detected during the recorded scans.",
                styles["BodyText"]
            ))

        story += [
            Spacer(1, 16),
            Paragraph("3. Methodology", styles["Heading2"]),
            Paragraph(
                "The tool periodically reads the host ARP table and builds a baseline IP-to-MAC mapping. "
                "A change in the MAC address associated with the same IP is treated as a strong ARP spoofing "
                "indicator. The default gateway mapping receives additional attention. Results are intended "
                "for defensive monitoring on networks you own or are authorized to administer.",
                styles["BodyText"]
            ),
            Spacer(1, 10),
            Paragraph(
                "<b>Safety note:</b> This project records network metadata and ARP information only. "
                "It does not capture, extract, or store passwords, authentication tokens, or packet payloads.",
                styles["BodyText"]
            )
        ]

        doc.build(story)
        messagebox.showinfo("PDF Report", f"Report generated:\n{filename}")

    def on_close(self):
        self.stop_monitoring()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = ARPShieldApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
