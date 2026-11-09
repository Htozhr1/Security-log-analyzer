from collections import Counter

# Security Log Analyzer
# Detect suspicious failed login attempts

logs = [
    "Failed login from 192.168.1.10",
    "Successful login from 192.168.1.20",
    "Failed login from 192.168.1.10",
    "Failed login from 192.168.1.30",
    "Failed login from 192.168.1.10",
    "Successful login from 192.168.1.40"
]

print("=== Security Log Analyzer ===")

failed_ips = []

for log in logs:
    if log.startswith("Failed login from "):
        ip = log.split()[-1]
        failed_ips.append(ip)

failed_counts = Counter(failed_ips)

print("\nFailed Login Attempts:")

for ip, count in failed_counts.items():
    print(f"{ip}: {count} failed attempts")

print("\nSuspicious IP Addresses:")

threshold = 3

for ip, count in failed_counts.items():
    if count >= threshold:
        print(f"ALERT: {ip} has {count} failed login attempts!")
