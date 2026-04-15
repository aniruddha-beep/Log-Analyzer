import re
import argparse
import logging
import json
import time
from collections import defaultdict
from typing import Dict, List


logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
# Setup basic logging

class LogAnalyzer:
    """
    A class to analyze authentication logs and detect suspicious activities.
    """
    def __init__(self, log_file: str, threshold: int = 3):
        self.log_file = log_file
        self.threshold = threshold
        self.failed_logins: List[str] = []
        self.ip_counts: Dict[str, int] = defaultdict(int)
        
        # Regex to match basic IPv4 addresses
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

    def analyze(self) -> None:
        """Reads the log file efficiently and processes failed login attempts."""
        logger.info(f"Starting analysis of '{self.log_file}' with threshold {self.threshold}")
        try:
            with open(self.log_file, 'r') as file:
                for line in file:
                    # We only care about failed passwords
                    if "Failed password" in line:
                        self.failed_logins.append(line.strip())
                        self._extract_and_count_ip(line)
                        
            logger.info("Log parsing completed.")
        except FileNotFoundError:
            logger.error(f"Error: The file '{self.log_file}' was not found.")
        except Exception as e:
            logger.error(f"An unexpected error occurred while reading the file: {e}")

    def _extract_and_count_ip(self, log_line: str) -> None:
        """Extracts the IP address from a single log line and updates the count."""
        match = self.ip_pattern.search(log_line)
        if match:
            ip = match.group()
            self.ip_counts[ip] += 1

    def get_suspicious_ips(self) -> Dict[str, int]:
        """Returns a dictionary of IPs that exceeded the failure threshold."""
        suspicious_ips = {ip: count for ip, count in self.ip_counts.items() if count >= self.threshold}
        return suspicious_ips

    def monitor_live(self) -> None:
        """Monitors the log file in real-time for suspicious activities."""
        print(f"[INFO] Monitoring '{self.log_file}' in real-time. Press Ctrl+C to stop.\n")

        try:
            with open(self.log_file, "r") as file:
                file.seek(0, 2)  # Move to end of file

                while True:
                    line = file.readline()

                    if not line:
                        time.sleep(0.1)
                        file.seek(file.tell())  # Clear the EOF flag in Windows
                        continue

                    if "Failed password" in line:
                        self._extract_and_count_ip(line)

                        match = self.ip_pattern.search(line)
                        if match:
                            ip = match.group()
                            count = self.ip_counts[ip]

                            print(f"[LIVE] {ip} → {count} failed attempts")

                            if count >= self.threshold:
                                print(f"[ALERT] Brute force suspected from {ip}")
        except KeyboardInterrupt:
            print("\n[INFO] Live monitoring stopped by user.")
        except FileNotFoundError:
            logger.error(f"Error: The file '{self.log_file}' was not found.")

    def export_to_json(self, output_file: str) -> None:
        """Exports the analysis results to a JSON file."""
        suspicious = self.get_suspicious_ips()
        report = {
            "analysis_metadata": {
                "source_file": self.log_file,
                "threshold_used": self.threshold,
                "total_failed_attempts_found": len(self.failed_logins),
                "total_suspicious_ips": len(suspicious)
            },
            "suspicious_ips": suspicious
        }

        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4)
            logger.info(f"Results successfully exported to '{output_file}'")
        except Exception as e:
            logger.error(f"Failed to export results to JSON: {e}")


def main():
    parser = argparse.ArgumentParser(description="Log Analyzer - Detect suspicious IPs from auth logs.")
    parser.add_argument("file", help="Path to the log file (e.g., auth.log)")
    parser.add_argument("-t", "--threshold", type=int, default=3, help="Failure threshold to flag an IP as suspicious (default: 3)")
    parser.add_argument("-o", "--output", help="Optional path to output the results as a JSON file")
    parser.add_argument("--live", action="store_true", help="Enable live monitoring mode")
    
    args = parser.parse_args()

    analyzer = LogAnalyzer(log_file=args.file, threshold=args.threshold)
    
    if args.live:
        analyzer.monitor_live()
        return

    analyzer.analyze()
    
    suspicious_ips = analyzer.get_suspicious_ips()
    
    # Output results to console
    if suspicious_ips:
        print("\nSUSPICIOUS IP ADDRESSES DETECTED")
        # Sort IPs by failed attempt count in descending order
        for ip, count in sorted(suspicious_ips.items(), key=lambda item: item[1], reverse=True):
            print(f"IP: {ip:<15} | Failed Attempts: {count}")
        print()
    else:
        logger.info("No suspicious IPs found exceeding the threshold.")

    # Export if requested
    if args.output:
        analyzer.export_to_json(args.output)


if __name__ == "__main__":
    main()
