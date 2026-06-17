import random
import csv
from datetime import datetime, timedelta

class LogGenerator:
    def __init__(self):
        self.normal_ips = [
            "192.168.1.10", "192.168.1.15", "192.168.1.22",
            "10.0.0.5", "10.0.0.8", "172.16.0.3"
        ]
        self.suspicious_ips = [
            "203.0.113.45", "198.51.100.23", "185.220.101.9"
        ]
        self.endpoints = [
            "/login", "/dashboard", "/api/users", "/api/orders",
            "/profile", "/settings", "/api/products", "/checkout"
        ]
        self.sensitive_endpoints = [
            "/admin", "/api/admin/users", "/config", "/.env", "/api/keys"
        ]

    def generate_normal_log(self, timestamp):
        """Generate a normal, everyday log entry"""
        return {
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": random.choice(self.normal_ips),
            "endpoint": random.choice(self.endpoints),
            "method": random.choice(["GET", "GET", "GET", "POST"]),
            "status_code": random.choice([200, 200, 200, 200, 304]),
            "response_time_ms": random.randint(50, 300),
            "user_agent": "Mozilla/5.0 (normal browser)"
        }

    def generate_brute_force_attack(self, base_timestamp, attacker_ip):
        """Simulate a brute force login attack - many failed logins in short time"""
        logs = []
        for i in range(25):
            ts = base_timestamp + timedelta(seconds=i * 2)
            logs.append({
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "ip": attacker_ip,
                "endpoint": "/login",
                "method": "POST",
                "status_code": 401,
                "response_time_ms": random.randint(20, 80),
                "user_agent": "python-requests/2.28"
            })
        return logs

    def generate_suspicious_access(self, base_timestamp, attacker_ip):
        """Simulate access to sensitive endpoints"""
        logs = []
        for endpoint in self.sensitive_endpoints:
            ts = base_timestamp + timedelta(seconds=random.randint(1, 60))
            logs.append({
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "ip": attacker_ip,
                "endpoint": endpoint,
                "method": "GET",
                "status_code": random.choice([403, 404, 401]),
                "response_time_ms": random.randint(20, 100),
                "user_agent": "curl/7.68.0"
            })
        return logs

    def generate_odd_hour_access(self, date, attacker_ip):
        """Simulate access at unusual hours (3am)"""
        logs = []
        ts = date.replace(hour=3, minute=random.randint(0, 59))
        logs.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": attacker_ip,
            "endpoint": "/api/users",
            "method": "GET",
            "status_code": 200,
            "response_time_ms": random.randint(100, 200),
            "user_agent": "python-requests/2.28"
        })
        return logs

    def generate_dataset(self, num_normal_logs=500, filename="data/server_logs.csv"):
        """Generate a complete dataset with normal + suspicious activity"""
        all_logs = []
        base_date = datetime.now() - timedelta(days=1)

        # Generate normal traffic throughout the day
        for i in range(num_normal_logs):
            ts = base_date + timedelta(minutes=random.randint(0, 1440))
            all_logs.append(self.generate_normal_log(ts))

        # Inject a brute force attack
        attack_time = base_date + timedelta(hours=14, minutes=30)
        all_logs.extend(self.generate_brute_force_attack(attack_time, "203.0.113.45"))

        # Inject suspicious endpoint scanning
        scan_time = base_date + timedelta(hours=10, minutes=15)
        all_logs.extend(self.generate_suspicious_access(scan_time, "198.51.100.23"))

        # Inject odd hour access
        all_logs.extend(self.generate_odd_hour_access(base_date, "185.220.101.9"))

        # Sort by timestamp
        all_logs.sort(key=lambda x: x["timestamp"])

        # Write to CSV
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=all_logs[0].keys())
            writer.writeheader()
            writer.writerows(all_logs)

        print(f"[*] Generated {len(all_logs)} log entries")
        print(f"[*] Saved to {filename}")
        print(f"[*] Injected: 1 brute force attack, 1 endpoint scan, 1 odd-hour access")
        
        return filename