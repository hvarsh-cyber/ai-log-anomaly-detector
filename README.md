# AI Log Anomaly Detector 🤖🔐
### Hybrid Rule-Based + Machine Learning Security Log Analysis

> Detects suspicious activity in server logs — brute force attacks, endpoint scanning, and odd-hour automated access — by combining SOC-style detection rules with Isolation Forest anomaly scoring.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-orange)
![Security](https://img.shields.io/badge/Security-SOC-red)

---

## 🚀 What it does

- 📊 **Generates realistic log datasets** with normal traffic and injected attack patterns
- 🧠 **Trains an Isolation Forest model** to score how unusual each log entry is
- 🛡️ **Applies SOC-style detection rules** for high-confidence flagging (request bursts, failure rates, odd-hour automated access)
- 📝 **Explains every detection** in plain English — not just a score, a reason
- 📁 **Outputs structured JSON reports** ready for SIEM ingestion or ticketing systems

---

## 🛡️ Attack Patterns Detected

| Pattern | Detection Logic |
|---|---|
| Brute force login | >10 requests from one IP within a 5-minute window |
| Credential stuffing | >50% failed request ratio from one IP |
| Sensitive endpoint scanning | 401/403 responses on `/admin`, `/.env`, `/config`, `/api/keys` |
| Automated odd-hour access | Script-like user agent (python-requests, curl) between 1am–5am |

---

## 🏗️ Architecture

```
ai-log-detector/
├── detector/
│   ├── log_generator.py      ← generates realistic test data
│   └── anomaly_detector.py   ← hybrid rule + ML detection engine
├── data/
│   └── server_logs.csv       ← generated log dataset
├── reports/                  ← JSON anomaly reports
└── main.py                   ← entry point
```

---

## ⚡ Quick Start

```bash
git clone https://github.com/hvarsh-cyber/ai-log-anomaly-detector.git
cd ai-log-anomaly-detector
python3 -m venv venv
source venv/bin/activate
pip install pandas numpy scikit-learn
python3 main.py
```

---

## 🧠 Why a Hybrid Approach?

Pure ML anomaly detection has a problem: forcing a fixed contamination percentage flags exactly that % of traffic regardless of whether anything is actually wrong — leading to false positives on completely normal behaviour.

This project uses well-established security detection rules (request rate, failure ratio, sensitive endpoint access, odd-hour automation) as the **ground truth for flagging**, and uses the Isolation Forest's `anomaly_score` purely to **rank and prioritise** findings by severity. This mirrors how production SOC tooling often works — deterministic rules for detection, ML for triage and prioritisation.

---

## 📊 Sample Output

```
[!] 2026-06-17 09:50:11 | IP: 203.0.113.45 | /login | Status: 401
    → High request volume from this IP (25 requests in 5 min)
    → High failure rate from this IP (100% failed)
    → Unauthorized/forbidden access attempt (HTTP 401)

[!] 2026-06-16 03:07:23 | IP: 185.220.101.9 | /api/users | Status: 200
    → Automated/scripted access during unusual hours (3:00) — user agent: python-requests/2.28
```

---

## 🔮 Roadmap

- [ ] Real-time log streaming support
- [ ] Slack/email alerting for high-severity findings
- [ ] Web dashboard for visualising anomaly trends
- [ ] Support for real-world log formats (Apache, Nginx, CloudTrail)
- [ ] Docker containerisation

---

## 👩‍💻 Author

**Himavarsha Sathyanarayana**  
Master of Cybersecurity @ Monash University  
2.6 years Security Automation @ EchoStar/Dish Network (Fortune 500)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-blue?style=flat&logo=linkedin)](https://linkedin.com/in/himavarsh-s-0a215b213)
[![GitHub](https://img.shields.io/badge/GitHub-black?style=flat&logo=github)](https://github.com/hvarsh-cyber)
