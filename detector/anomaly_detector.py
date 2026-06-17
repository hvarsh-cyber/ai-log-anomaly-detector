import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import json
from datetime import datetime

class AnomalyDetector:
    def __init__(self, log_file="data/server_logs.csv"):
        self.log_file = log_file
        self.df = None
        self.model = IsolationForest(contamination="auto", random_state=42, n_estimators=200)
        self.anomalies = []

    def load_logs(self):
        """Load logs from CSV"""
        print(f"\n[*] Loading logs from {self.log_file}")
        self.df = pd.read_csv(self.log_file)
        self.df["timestamp"] = pd.to_datetime(self.df["timestamp"])
        print(f"[*] Loaded {len(self.df)} log entries")

    def engineer_features(self):
        """Convert raw logs into numerical features the AI model can understand"""
        print(f"\n[*] Engineering features for ML model")
        
        df = self.df.copy()
        
        # Feature 1: Hour of day (helps detect odd-hour access)
        df["hour"] = df["timestamp"].dt.hour
        
        # Feature 2: Requests per IP within a 5-minute rolling window (catches bursts, not just busy users)
        df = df.sort_values("timestamp").reset_index(drop=True)
        df["requests_in_5min"] = 0

        for ip in df["ip"].unique():
            ip_mask = df["ip"] == ip
            ip_times = df.loc[ip_mask, "timestamp"]
            counts = ip_times.apply(lambda t: ((ip_times >= t - pd.Timedelta(minutes=5)) & (ip_times <= t)).sum())
            df.loc[ip_mask, "requests_in_5min"] = counts.values

        df["requests_per_ip"] = df["requests_in_5min"]
        
        # Feature 3: Failed request ratio per IP (helps detect brute force/scanning)
        df["is_failed"] = df["status_code"].apply(lambda x: 1 if x >= 400 else 0)
        failed_ratio = df.groupby("ip")["is_failed"].transform("mean")
        df["failed_ratio_per_ip"] = failed_ratio
        
        # Feature 4: Encode endpoint as a number
        le_endpoint = LabelEncoder()
        df["endpoint_encoded"] = le_endpoint.fit_transform(df["endpoint"])
        
        # Feature 5: Response time
        df["response_time_ms"] = df["response_time_ms"]
        
        # Feature 6: Status code
        df["status_code_num"] = df["status_code"]
        
        self.df = df
        self.feature_columns = [
            "hour", "requests_per_ip", "failed_ratio_per_ip", 
            "endpoint_encoded", "response_time_ms", "status_code_num"
        ]
        
        print(f"[*] Created {len(self.feature_columns)} features: {', '.join(self.feature_columns)}")

    def train_and_detect(self):
        """Train the Isolation Forest model and detect anomalies"""
        print(f"\n[*] Training Isolation Forest model...")
        
        X = self.df[self.feature_columns]
        
        self.model.fit(X)
        anomaly_scores = self.model.score_samples(X)
        self.df["anomaly_score"] = anomaly_scores
        
        # High-confidence security rules trigger an anomaly directly — these are
        # well-established OWASP/SOC detection patterns, not statistical guesses.
        # The ML anomaly_score is kept on every row to rank and explain severity,
        # rather than acting as a gatekeeper that could veto a real attack pattern.
        high_confidence_rule = (
            (self.df["requests_per_ip"] > 10) |
            (self.df["failed_ratio_per_ip"] > 0.5) |
            ((self.df["hour"] >= 1) & (self.df["hour"] <= 5) & (self.df["status_code"] >= 400)) |
            ((self.df["hour"] >= 1) & (self.df["hour"] <= 5) & (self.df["user_agent"].str.contains("python|curl|requests", case=False, na=False)))
        )
        
        self.df["rule_flagged"] = high_confidence_rule
        self.df["is_anomaly"] = high_confidence_rule
        
        anomaly_count = self.df["is_anomaly"].sum()
        print(f"[*] Model trained on {len(X)} log entries")
        print(f"[!] Detected {anomaly_count} anomalies ({anomaly_count/len(X)*100:.1f}% of traffic)")

    def explain_anomaly(self, row):
        """Generate human-readable explanation for why this was flagged"""
        reasons = []
        
        if row["requests_per_ip"] > 10:
            reasons.append(f"High request volume from this IP ({row['requests_per_ip']} requests in 5 min)")
        
        if row["failed_ratio_per_ip"] > 0.5:
            reasons.append(f"High failure rate from this IP ({row['failed_ratio_per_ip']*100:.0f}% failed)")
        
        if row["hour"] >= 1 and row["hour"] <= 5:
            if row["status_code"] >= 400:
                reasons.append(f"Access during unusual hours ({row['hour']}:00)")
            if "python" in str(row["user_agent"]).lower() or "curl" in str(row["user_agent"]).lower() or "requests" in str(row["user_agent"]).lower():
                reasons.append(f"Automated/scripted access during unusual hours ({row['hour']}:00) — user agent: {row['user_agent']}")
        
        if row["status_code"] in [401, 403]:
            reasons.append(f"Unauthorized/forbidden access attempt (HTTP {row['status_code']})")
        
        if not reasons:
            reasons.append("Unusual combination of request characteristics")
        
        return reasons

    def generate_report(self):
        """Generate a detailed report of all anomalies found"""
        print(f"\n[*] Generating anomaly report...")
        
        anomalies_df = self.df[self.df["is_anomaly"] == True].copy()
        anomalies_df = anomalies_df.sort_values("anomaly_score")
        
        report = {
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_logs_analyzed": len(self.df),
            "total_anomalies": len(anomalies_df),
            "anomalies": []
        }
        
        print(f"\n{'='*60}")
        print(f"ANOMALIES DETECTED")
        print(f"{'='*60}")
        
        for idx, row in anomalies_df.iterrows():
            reasons = self.explain_anomaly(row)
            
            anomaly_entry = {
                "timestamp": row["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                "ip": row["ip"],
                "endpoint": row["endpoint"],
                "status_code": int(row["status_code"]),
                "anomaly_score": float(row["anomaly_score"]),
                "reasons": reasons
            }
            report["anomalies"].append(anomaly_entry)
            
            print(f"\n[!] {row['timestamp']} | IP: {row['ip']} | {row['endpoint']} | Status: {row['status_code']}")
            for reason in reasons:
                print(f"    → {reason}")
        
        filename = f"reports/anomaly_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
        
        print(f"\n{'='*60}")
        print(f"[*] Full report saved to {filename}")
        print(f"{'='*60}")
        
        return report

    def run(self):
        """Run the full detection pipeline"""
        self.load_logs()
        self.engineer_features()
        self.train_and_detect()
        self.generate_report()