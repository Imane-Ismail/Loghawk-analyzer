import os
import re
from datetime import datetime

class LogHawk:
    def __init__(self):
        self.suspicious_patterns = [
            # Authentication and brute force
            ("Failed Login", r"Failed login|authentication failed"),
            ("Brute Force Attempt", r"Multiple failed login attempts"),
            
            # PowerShell abuse
            ("PowerShell Encoded", r"powershell.*-enc"),
            ("PowerShell Download", r"powershell.*Invoke-WebRequest|Invoke-Expression|wget|curl"),

            # Network and C2
            ("Netcat Usage", r"\snc\s"),
            ("C2 Beaconing", r"Outbound connection|known C2|DNS resolution of known C2"),

            # File and process indicators
            ("Suspicious File Write", r"C:\\.*\\.*\\(dropper|evil).*\.exe|\.dll"),
            ("Suspicious Process Spawning", r"spawn of child process.*(cmd|powershell|wmic|mshta)"),

            # Threat intelligence mapping
            ("ATT&CK Technique Detected", r"MITRE ATT&CK MAPPING:"),

            # Web attack indicators
            ("SQL Injection Attempt", r"('|\%27)[\s]*or[\s]+1=1|UNION\s+SELECT|select\s+\*\s+from"),
            ("Cross-Site Scripting (XSS)", r"<script>|%3Cscript%3E|onerror=|alert\("),
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
        # Look for ISO 8601 or Windows log formats
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
