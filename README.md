# 🛡️ Sentinel: Python Log Analyzer

**Sentinel** is a simple and robust Python utility designed to analyze server authentication logs (e.g., `auth.log`). It detects suspicious IP addresses associated with brute-force attacks (repeated failed logins) and can monitor your logs in real-time!

## 🚀 Getting Started

You only need **Python 3.8+** to run this project. No external libraries are needed.

### 1. Basic Commands

Run the script from the command line, pointing it to your log file:

```powershell
# Analyze an existing log file
python log_analyzer.py auth.log

# Change the threshold (e.g., alert after 5 failed logins)
python log_analyzer.py auth.log --threshold 5

# Export results to JSON
python log_analyzer.py auth.log --output report.json
```

### 2. Live Monitoring (Real-Time)

You can run Sentinel in **Live Mode** to actively monitor your logs for ongoing attacks. It will run continuously in the background and alert you the second a brute-force threshold is met.

**Step 1:** Start the live monitor.
```powershell
python log_analyzer.py auth.log --live
```
*(Leave this terminal window open and running)*

**Step 2:** Test it by simulating an attack! Open a **second terminal window** and run this command 3 times to safely inject a fake failed login into the log file:
```powershell
python -c "open('auth.log', 'a', encoding='utf-8').write('Failed password for invalid user admin from 192.168.1.15 port 22 ssh2\n')"
```

Go back to your first terminal, and you will see the live alerts pop up! Press `Ctrl + C` in the first terminal to stop monitoring.

## 🧪 Running Tests

To ensure the utility is functioning correctly, you can run the included test suite:

```powershell
python -m unittest test_log_analyzer.py
```
