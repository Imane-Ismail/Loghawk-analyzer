import os
import re
from datetime import datetime

class LogHawk:
    def __init__(self):
        self.suspicious_patterns = [
            ("Failed Login", r"Failed login|authentication failed"),
            ("PowerShell Encoded", r"powershell.*-enc"),
            ("Netcat Usage", r"nc\s"),
        ]

    def analyze_logs(self, filepath):
        alerts = []
        summary = {}

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for i, line in enumerate(lines, start=1):
            for category, pattern in self.suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    timestamp = self.extract_timestamp(line)
                    alerts.append({
                        "Category": category,
                        "Line Number": i,
                        "Log Entry": line.strip(),
                        "Timestamp": timestamp or "N/A"
                    })
                    summary[category] = summary.get(category, 0) + 1

        return alerts, summary

    def extract_timestamp(self, line):
        match = re.search(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", line)
        return match.group(0) if match else None

    def scan_directory(self, directory):
        print(f"[+] Scanning directory: {directory}")
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(('.log', '.txt', '.json')):
                    path = os.path.join(root, file)
                    print(f"\n--- Analyzing {path} ---")
                    alerts, summary = self.analyze_logs(path)
                    if alerts:
                        for alert in alerts:
                            print(f"[{alert['Category']}] {alert['Timestamp']} - Line {alert['Line Number']}: {alert['Log Entry']}")
                        print("\n=== Summary of Detected Events ===")
                        for category, count in summary.items():
                            print(f"{category}: {count} event(s)")
                    else:
                        print("[-] No suspicious events detected.")
