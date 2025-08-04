import os
import re
from datetime import datetime

class LogHawk:
    def __init__(self):
        # Pattern: (Description, Regex Pattern, MITRE ATT&CK ID)
        self.suspicious_patterns = [
            ("Failed Login / Brute Force", r"Failed login|authentication failed", "T1110"),
            ("PowerShell Encoded Command", r"powershell.*-enc", "T1059.001"),
            ("Netcat Usage", r"\bnc\b\s", "T1105"),
            ("Web Shell Execution", r"(cmd=|eval\(|base64_decode)", "T1505.003"),
            ("Suspicious POST Request", r"POST\s.+\sHTTP/1\.1", "T1041"),
            ("SMB / Lateral Movement", r"\b(wmic|psexec|smbclient)\b", "T1021"),
            ("Beaconing to External IP", r"(GET|POST)\s.*(\/|\.)[a-z0-9\-\.]{3,}\.(com|net|ru|cn)", "T1071.001"),
            ("Encoded Payload (Base64)", r"[A-Za-z0-9+/=]{200,}", "T1027"),
        ]

    def analyze_logs(self, filepath):
        alerts = []
        summary = {}

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for i, line in enumerate(lines, start=1):
            for desc, pattern, mitre_id in self.suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    timestamp = self.extract_timestamp(line)
                    alert = {
                        "Category": desc,
                        "MITRE ATT&CK": mitre_id,
                        "Line Number": i,
                        "Log Entry": line.strip(),
                        "Timestamp": timestamp or "N/A"
                    }
                    alerts.append(alert)
                    summary[desc] = summary.get(desc, 0) + 1

        return alerts, summary

    def extract_timestamp(self, line):
        # Matches formats like 2025-08-04 10:22:33 or 2025-08-04T10:22:33
        match = re.search(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", line)
        return match.group(0) if match else None

    def scan_directory(self, directory):
        print(f"[+] Scanning directory: {directory}")
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(('.log', '.txt', '.json', '.csv')):
                    path = os.path.join(root, file)
                    print(f"\n--- Analyzing {path} ---")
                    alerts, summary = self.analyze_logs(path)
                    if alerts:
                        for alert in alerts:
                            print(f"[{alert['Category']} | {alert['MITRE ATT&CK']}] {alert['Timestamp']} - Line {alert['Line Number']}: {alert['Log Entry']}")
                        print("\n=== Summary of Detected Events ===")
                        for category, count in summary.items():
                            print(f"{category}: {count} event(s)")
                    else:
                        print("[-] No suspicious events detected.")
