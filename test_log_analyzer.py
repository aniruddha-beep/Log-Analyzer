import unittest
import os
import json
from log_analyzer import LogAnalyzer

class TestLogAnalyzer(unittest.TestCase):
    def setUp(self):
        # Create a temporary mock log file for testing
        self.test_log_file = "test_auth.log"
        self.test_json_file = "test_output.json"
        
        with open(self.test_log_file, "w") as f:
            f.write("Failed password for invalid user admin from 192.168.1.10 port 22 ssh2\n")
            f.write("Failed password for invalid user admin from 192.168.1.10 port 22 ssh2\n")
            f.write("Failed password for invalid user root from 192.168.1.11 port 22 ssh2\n")
            f.write("Accepted password for user from 192.168.1.12 port 22 ssh2\n") # Shouldn't be counted
            f.write("Failed password for invalid user test from 192.168.1.10 port 22 ssh2\n")

    def tearDown(self):
        # Clean up temporary test files
        if os.path.exists(self.test_log_file):
            os.remove(self.test_log_file)
        if os.path.exists(self.test_json_file):
            os.remove(self.test_json_file)

    def test_log_parsing(self):
        analyzer = LogAnalyzer(log_file=self.test_log_file, threshold=3)
        analyzer.analyze()
        
        # Test total failed logins logged (should be 4)
        self.assertEqual(len(analyzer.failed_logins), 4)

        # Test IP extraction logic
        self.assertEqual(analyzer.ip_counts["192.168.1.10"], 3)
        self.assertEqual(analyzer.ip_counts["192.168.1.11"], 1)
        self.assertNotIn("192.168.1.12", analyzer.ip_counts) # Accepted pass, shouldn't be here

    def test_suspicious_ip_detection(self):
        # Test with threshold = 3
        analyzer_high_threshold = LogAnalyzer(log_file=self.test_log_file, threshold=3)
        analyzer_high_threshold.analyze()
        suspicious_high = analyzer_high_threshold.get_suspicious_ips()
        
        self.assertIn("192.168.1.10", suspicious_high)
        self.assertNotIn("192.168.1.11", suspicious_high)
        self.assertEqual(len(suspicious_high), 1)

        # Test with threshold = 1
        analyzer_low_threshold = LogAnalyzer(log_file=self.test_log_file, threshold=1)
        analyzer_low_threshold.analyze()
        suspicious_low = analyzer_low_threshold.get_suspicious_ips()
        
        self.assertIn("192.168.1.10", suspicious_low)
        self.assertIn("192.168.1.11", suspicious_low)
        self.assertEqual(len(suspicious_low), 2)

    def test_json_export(self):
        analyzer = LogAnalyzer(log_file=self.test_log_file, threshold=2)
        analyzer.analyze()
        
        # Export to JSON
        analyzer.export_to_json(self.test_json_file)
        
        # Verify JSON was created and has correct contents
        self.assertTrue(os.path.exists(self.test_json_file))
        
        with open(self.test_json_file, 'r') as f:
            data = json.load(f)
            
        self.assertIn("analysis_metadata", data)
        self.assertIn("suspicious_ips", data)
        self.assertEqual(data["analysis_metadata"]["total_failed_attempts_found"], 4)
        self.assertEqual(data["suspicious_ips"]["192.168.1.10"], 3)


if __name__ == "__main__":
    unittest.main()
