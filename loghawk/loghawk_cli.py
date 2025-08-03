import sys
import os
import pyfiglet
import argparse
from .scanner import LogHawk

def run_analysis(input_path):
    loghawk = LogHawk()

    if os.path.isdir(input_path):
        loghawk.scan_directory(input_path)
    elif os.path.isfile(input_path):
        alerts, summary = loghawk.analyze_logs(input_path)
        if alerts:
            print(f"\n[+] Suspicious events found in: {input_path}\n")
            for alert in alerts:
                print(f"[{alert['Category']}] {alert['Timestamp']} - Line {alert['Line Number']}: {alert['Log Entry']}")
            print("\n=== Summary of Detected Events ===")
            for category, count in summary.items():
                print(f"{category}: {count} event(s)")
        else:
            print("[-] No suspicious events detected.")
    else:
        print("❌ Invalid path. Please provide a valid log file or directory.")

def main():
    ascii_banner = pyfiglet.figlet_format("LogHawk")
    print(ascii_banner)
    print("Your Log Analysis Tool\n")

    parser = argparse.ArgumentParser(description="LogHawk - Scan log files for suspicious activity.")
    parser.add_argument("--input", type=str, help="Path to the log file or directory", required=True)
    args = parser.parse_args()

    run_analysis(args.input)

if __name__ == "__main__":
    main()
