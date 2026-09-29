# Network IDS Simulation — Complete Project Documentation

## Table of Contents
- [Project Report](#project-report)
- [Detection Scenarios](#detection-scenarios)
- [SOC Analyst Workflow](#soc-analyst-workflow)
- [IDS vs IPS Comparison](#ids-vs-ips)
- [Signature vs Anomaly Detection](#signature-vs-anomaly)
- [Confusion Matrix & Metrics](#confusion-matrix)
- [MITRE ATT&CK Mapping](#mitre-attck)
- [SIEM Integration](#siem-integration)
- [Security & Privacy](#security--privacy)
- [GitHub Upload Strategy](#github-upload-strategy)
- [Resume & LinkedIn Proof](#resume--linkedin)
- [Interview Preparation](#interview-preparation)
- [Future Improvements](#future-improvements)

---

## Project Report

### Abstract

This project presents a Network Intrusion Detection System (IDS) simulation that demonstrates defensive cybersecurity principles through synthetic traffic analysis. The system implements a hybrid detection approach combining signature-based rules, statistical anomaly detection, and optional machine learning classification. Built with Python (FastAPI) and React, it provides a complete SOC-style workflow including real-time monitoring, alert generation, incident investigation, and risk scoring — all operating safely on synthetic data.

### Introduction

Network security remains one of the most critical challenges in modern computing. As organizations connect more devices and services, the attack surface grows exponentially. Intrusion Detection Systems serve as a fundamental layer of defense, monitoring network traffic for indicators of compromise and alerting security analysts to potential threats.

This project simulates a production-grade Network IDS with the following key innovations:
- **Hybrid Detection**: Combining three detection methods for comprehensive coverage
- **Risk Scoring**: Quantified risk assessment rather than binary classification
- **Alert Correlation**: Grouping related alerts to reduce analyst fatigue
- **SOC Workflow**: Complete investigation lifecycle management

### Proposed System

The system processes network flow records through a multi-stage pipeline:

1. **Traffic Generation**: Synthetic flow records representing normal and suspicious patterns
2. **Feature Extraction**: 15 engineered features capturing security-relevant metrics
3. **Detection Layer**: Three parallel detection engines (rules, anomaly, ML)
4. **Risk Scoring**: Weighted combination of detection outputs (0-100 scale)
5. **Alert Management**: Severity-based alerts with investigation recommendations
6. **Dashboard**: Real-time visualization and analyst tools

### Results

The system successfully:
- Generates 5,000+ realistic flow records across 11 scenario types
- Detects all 6 suspicious scenarios with appropriate rule triggers
- Assigns accurate risk scores correlating with ground-truth labels
- Provides a professional dashboard with 8+ chart types
- Supports complete SOC investigation workflow

### Conclusion

This project demonstrates that a functional IDS can be built using open-source tools and synthetic data. The hybrid approach provides stronger detection coverage than any single method alone, and the SOC dashboard enables efficient analyst workflows. While synthetic data has limitations compared to real network traffic, this simulation effectively teaches core IDS concepts applicable to production environments.

---

## Detection Scenarios

### Scenario A: Normal HTTPS Browsing
- **Input**: TCP, dest port 443, 50 packets, 35KB, 2.5s duration, 2 connections, 0 failures
- **Features**: bytes/sec=14000, packets/sec=20, failure_ratio=0, syn_ratio=0.02
- **Rule Triggered**: None
- **Risk Score**: 0-5
- **Classification**: NORMAL
- **Expected Alert**: None

### Scenario B: Normal DNS Query
- **Input**: UDP, dest port 53, 4 packets, 512 bytes, 0.05s, 1 connection, 0 failures
- **Features**: bytes/sec=10240, packets/sec=80, failure_ratio=0, syn_ratio=0
- **Rule Triggered**: None
- **Risk Score**: 0-10
- **Classification**: NORMAL
- **Expected Alert**: None

### Scenario C: Repeated Failed Connections
- **Input**: TCP, dest port 22, 8 packets, 960 bytes, 3.0s, 50 connections, 45 failures
- **Features**: failure_ratio=0.9, connection_rate=16.7
- **Rule Triggered**: IDS-002 (Repeated Failed Connections)
- **Risk Score**: 60-80
- **Classification**: HIGH RISK
- **Expected Alert**: HIGH severity, "investigate brute force"

### Scenario D: High Connection Rate
- **Input**: TCP, dest port 80, 15 packets, 12KB, 0.05s, 250 connections, 20 failures
- **Features**: connection_rate=5000, packets/sec=300
- **Rule Triggered**: IDS-001 (High Connection Rate)
- **Risk Score**: 65-85
- **Classification**: HIGH RISK
- **Expected Alert**: HIGH severity, "rate exceeded baseline"

### Scenario E: Multi-Port Probing Pattern
- **Input**: TCP, random dest ports, 3 packets, 180 bytes, 0.01s, 100 connections, 90 failures
- **Features**: unique_destination_ports=100 (over session), failure_ratio=0.9
- **Rule Triggered**: IDS-003 (Multi-Port Activity) + IDS-002
- **Risk Score**: 70-90
- **Classification**: HIGH RISK to CRITICAL
- **Expected Alert**: MEDIUM-HIGH, "port scanning pattern"

### Scenario F: SYN-Heavy Pattern
- **Input**: TCP, dest port 80, 500 packets, syn_count=450, 1.0s
- **Features**: syn_ratio=0.9, packets/sec=500
- **Rule Triggered**: IDS-004 (SYN-Heavy Pattern)
- **Risk Score**: 65-85
- **Classification**: HIGH RISK
- **Expected Alert**: HIGH severity, "SYN flood indicator"

### Scenario G: High Traffic Volume
- **Input**: TCP, dest port 443, 50000 packets, 75MB, 50s
- **Features**: bytes_per_second=1,500,000
- **Rule Triggered**: IDS-006 (High Traffic Volume)
- **Risk Score**: 55-75
- **Classification**: SUSPICIOUS to HIGH RISK
- **Expected Alert**: HIGH severity, "data exfiltration risk"

---

## SOC Analyst Workflow

```
Network Event
      ↓
IDS Detection (rules + anomaly + ML)
      ↓
Alert Generated (severity + risk score)
      ↓
SOC Queue (dashboard)
      ↓
Tier 1 Analyst Triage
  ├── Quick assessment: Is this real or FP?
  ├── Check source IP reputation
  └── Review matched rules & anomaly details
      ↓
Investigation
  ├── Review historical activity for source IP
  ├── Check endpoint telemetry (if available)
  ├── Compare with baseline behavior
  ├── Check authentication logs
  └── Review firewall records
      ↓
Determine Severity & Action
  ├── RESOLVED — Confirmed benign, close alert
  ├── FALSE_POSITIVE — Tune detection rules
  └── ESCALATE — True positive, create incident
      ↓
Document Everything
  ├── Add analyst notes
  ├── Record investigation steps taken
  └── Update status with timestamps
```

### Tier 1 SOC Responsibilities
1. Monitor dashboard for new alerts
2. Triage alerts by severity (CRITICAL first)
3. Perform initial investigation (5-15 minutes per alert)
4. Escalate true positives to Tier 2
5. Document findings and close false positives
6. Identify recurring patterns for rule tuning

---

## IDS vs IPS

| Feature | IDS (this project) | IPS |
|---------|-------------------|-----|
| **Purpose** | Detect & Alert | Detect, Alert & Prevent |
| **Action** | Passive monitoring | Active blocking |
| **Placement** | Out-of-band (mirror port) | Inline (on traffic path) |
| **Risk** | No traffic disruption | May block legitimate traffic |
| **False Positive Impact** | Analyst workload | Service disruption |
| **Use Case** | Monitoring, forensics | Real-time prevention |

> **Why IDS for this project?** Automatically blocking traffic requires deep integration with network infrastructure and carries the risk of service disruption. An IDS simulation is safer, more educational, and demonstrates the detection pipeline without production risks.

---

## Signature vs Anomaly Detection {#signature-vs-anomaly}

| Aspect | Signature-Based | Anomaly-Based | Hybrid (this project) |
|--------|----------------|---------------|----------------------|
| **Approach** | Match known patterns | Detect deviations | Both combined |
| **Known Threats** | ✅ Excellent | ⚠️ May miss specific IoCs | ✅ Covered |
| **Unknown Threats** | ❌ Cannot detect | ✅ Can detect novel patterns | ✅ Covered |
| **False Positives** | Low (well-defined) | Higher (baseline drift) | Balanced |
| **Explainability** | High (rule name) | Medium (statistics) | High |
| **Speed** | Very fast | Moderate | Moderate |
| **Maintenance** | Requires rule updates | Requires baseline tuning | Both |

---

## Confusion Matrix & Metrics {#confusion-matrix}

|  | **Predicted: Normal** | **Predicted: Suspicious** |
|--|----------------------|--------------------------|
| **Actual: Normal** | True Negative (TN) | False Positive (FP) |
| **Actual: Suspicious** | False Negative (FN) | True Positive (TP) |

### Metric Definitions

- **Precision** = TP / (TP + FP) — "Of alerts fired, how many were real?"
- **Recall** = TP / (TP + FN) — "Of real attacks, how many did we catch?"
- **F1 Score** = 2 × (Precision × Recall) / (Precision + Recall) — Harmonic mean
- **ROC-AUC** = Area under ROC curve — Overall ranking quality

> **Why security teams focus on recall:** A missed attack (false negative) can lead to a breach. High recall ensures maximum detection coverage. However, very low precision creates alert fatigue — analysts waste time on false positives. The F1 score balances both concerns.

---

## MITRE ATT&CK Mapping {#mitre-attck}

| Alert Pattern | Tactic | Technique | ID |
|-------------|--------|-----------|------|
| Multi-port probing | Reconnaissance | Network Service Discovery | T1046 |
| Failed auth attempts | Credential Access | Brute Force | T1110 |
| SYN flood pattern | Impact | Network Denial of Service | T1498 |
| Unusual port activity | Command & Control | Non-Standard Port | T1571 |
| High data volume out | Exfiltration | Exfiltration Over C2 Channel | T1041 |

> **Important:** A statistical anomaly does NOT automatically prove a specific attack technique. ATT&CK mapping should only be applied when sufficient evidence and context support the classification.

---

## SIEM Integration

### Conceptual Architecture
```
IDS Alert → JSON Format → Log Forwarder (syslog/API) → SIEM → Correlation → SOC Analyst
```

### Sample JSON Alert for SIEM
```json
{
  "alert_id": "ALT-10021",
  "timestamp": "2024-01-15T10:30:00Z",
  "source_ip": "192.0.2.15",
  "destination_ip": "198.51.100.20",
  "source_port": 49152,
  "destination_port": 443,
  "protocol": "TCP",
  "severity": "HIGH",
  "rule_id": "IDS-001",
  "rule_name": "High Connection Rate",
  "risk_score": 78,
  "anomaly_score": 65.4,
  "description": "Connection rate significantly exceeded configured baseline.",
  "status": "NEW"
}
```

---

## Security & Privacy

1. **Synthetic Data Only** — No real network traffic captured or stored
2. **No Payload Storage** — Only flow metadata (IPs, ports, sizes), not packet contents
3. **Dashboard Protection** — Authentication recommended for production
4. **Authorization** — Analyst roles should restrict who can modify alert status
5. **Encryption** — HTTPS recommended for production API endpoints
6. **Log Protection** — Security events themselves contain sensitive data
7. **Input Sanitization** — Pydantic models validate all API inputs
8. **Rate Limiting** — Recommended for production to prevent API abuse
9. **Environment Variables** — Secrets stored in .env, not in code
10. **Audit Trail** — All status changes logged with timestamps and analyst names
11. **Least Privilege** — Read-only dashboard access, write access for investigations
12. **IDS Data Sensitivity** — IDS alert data reveals network topology and security posture; protect accordingly

---

## GitHub Upload Strategy

### Repository Setup
```bash
# Initialize
cd Network-IDS-Simulation
git init
git remote add origin https://github.com/YOUR_USERNAME/Network-Intrusion-Detection-System-Simulation.git

# Recommended commits (in order)
git add .gitignore README.md requirements.txt .env.example run.py
git commit -m "Initialize network IDS simulation project"

git add simulator/
git commit -m "Add synthetic traffic dataset generator and simulator"

git add ids/feature_extractor.py
git commit -m "Implement network feature extraction"

git add ids/rule_engine.py
git commit -m "Implement signature-based detection rules (8 rules)"

git add ids/anomaly_detector.py
git commit -m "Add statistical anomaly detection engine"

git add ids/risk_engine.py ids/alert_engine.py ids/correlation.py
git commit -m "Implement hybrid risk scoring and alert generation"

git add ml/
git commit -m "Add optional ML detection (RF, LR, Isolation Forest)"

git add backend/
git commit -m "Build FastAPI backend with REST API and SSE"

git add frontend/
git commit -m "Create React SOC dashboard with dark theme"

git add tests/
git commit -m "Add comprehensive test suite (48 tests)"

git add docs/ reports/
git commit -m "Complete documentation and project report"

# Push
git branch -M main
git push -u origin main
```

### Repository Description
"Defensive network intrusion detection simulation featuring synthetic traffic generation, signature-based and anomaly-based detection, risk scoring, alert correlation, SOC analytics, and optional machine learning."

### GitHub Topics
`cybersecurity` `intrusion-detection` `ids` `network-security` `soc` `python` `anomaly-detection` `machine-learning` `security-analytics` `threat-detection` `defensive-security`

---

## Resume & LinkedIn Proof {#resume--linkedin}

### Resume Bullet Points

1. **Developed a hybrid Network IDS simulation** processing 5,000+ synthetic flow records through a 3-layer detection pipeline (signature rules, statistical anomaly detection, Random Forest ML), achieving configurable risk scoring and SOC-style alert management via a FastAPI + React full-stack application.

2. **Engineered 15 network security features** (connection rate, failure ratio, SYN ratio, bytes/sec) and implemented 8 configurable detection rules to identify patterns including high connection rates, failed authentication bursts, port scanning, and SYN floods — with weighted hybrid risk scoring (0–100) and alert correlation.

3. **Built a professional SOC dashboard** with React and Recharts featuring real-time SSE updates, 8 analytical charts (traffic timeline, severity distribution, risk histogram), alert investigation workflow with analyst notes, and a complete incident lifecycle (NEW → INVESTIGATING → RESOLVED/FALSE_POSITIVE).

### 2-Line Project Description
Built a complete Network Intrusion Detection System simulation with hybrid detection (signature + anomaly + ML), processing synthetic traffic through a FastAPI backend and React SOC dashboard. Demonstrates defensive cybersecurity, network traffic analysis, risk scoring, and alert management for SOC analyst workflows.

### LinkedIn Project Description
🛡️ **Network Intrusion Detection System (IDS) Simulation**

Designed and built a full-stack defensive cybersecurity project simulating a production-grade Network IDS. The system processes synthetic network traffic through a multi-layered detection pipeline:

🔍 **Signature Detection** — 8 configurable rules for known attack patterns
📊 **Anomaly Detection** — Statistical Z-score analysis against baseline behavior
🤖 **Machine Learning** — Random Forest, Logistic Regression, and Isolation Forest models
⚖️ **Hybrid Risk Scoring** — Weighted combination producing 0-100 risk scores
🚨 **Alert Management** — Severity-based alerts with SOC investigation workflow
📈 **SOC Dashboard** — Real-time React dashboard with traffic analytics, alert triage, and incident management

Tech Stack: Python, FastAPI, React, scikit-learn, SQLite, SSE
Concepts: Network Security, IDS/IPS, SOC Operations, Feature Engineering, Anomaly Detection

### Technical Skills Demonstrated
- Network Security & Traffic Analysis
- Intrusion Detection Systems (IDS/IPS)
- SOC Operations & Alert Triage
- Python Full-Stack Development
- Machine Learning (Classification, Anomaly Detection)
- Feature Engineering
- REST API Design
- React Dashboard Development
- Database Design (SQL)
- Security Analytics & Risk Scoring

---

## Interview Preparation

### Q1: Explain your project.

**A:** I built a Network Intrusion Detection System simulation that monitors synthetic network traffic for suspicious patterns. The system has three detection layers: first, a signature engine with 8 configurable rules that match known patterns like high connection rates or SYN floods. Second, a statistical anomaly detector that calculates Z-scores against a baseline of normal traffic. Third, an optional machine learning layer using Random Forest classification.

These three detection outputs are combined using a weighted hybrid risk scoring engine that produces a 0-100 risk score. When the score exceeds a threshold, the system generates an alert with a severity level, investigation recommendations, and stores everything in a database. I built a React SOC dashboard where analysts can view traffic analytics, triage alerts, add investigation notes, and mark alerts as resolved or false positive.

Everything runs on synthetic data using RFC 5737 documentation IP ranges — no real networks are scanned or attacked. I generated 5,000+ flow records across 11 scenario types covering normal web/DNS/SSH traffic and suspicious patterns like port scanning, brute force, and SYN floods.

### Q2: What is the difference between signature-based and anomaly-based detection?

**A:** Signature-based detection matches traffic against known patterns — like checking if the connection rate exceeds 50 per second. It's fast, explainable, and has low false positives for well-defined patterns, but it can't detect novel attacks it hasn't seen before.

Anomaly-based detection establishes a baseline of "normal" behavior and flags deviations. In my project, I calculate Z-scores for metrics like byte rate, connection rate, and SYN ratio. If a flow deviates significantly from the baseline, it gets a high anomaly score. This can catch unknown patterns, but it also generates more false positives because unusual doesn't always mean malicious — a backup server might legitimately spike traffic.

That's why I used a hybrid approach combining both methods with configurable weights, which provides stronger coverage than either method alone.

### Q3: How does your risk scoring work?

**A:** I use a weighted combination of three detection outputs. With ML enabled, the weights are: rule-based 40%, anomaly 30%, ML 30%. Without ML, it's 60% rules and 40% anomaly. The rule score is based on the maximum severity of triggered rules — HIGH maps to 80, CRITICAL to 95. The anomaly score comes directly from the Z-score calculation scaled to 0-100. The ML score is the model's probability output scaled to 100.

The final score maps to classifications: 0-20 is NORMAL, 21-40 is LOW RISK, 41-60 is SUSPICIOUS, 61-80 is HIGH RISK, and 81-100 requires CRITICAL INVESTIGATION. These thresholds are configurable — in a real SOC, they'd be calibrated based on the organization's risk tolerance and alert volume.

### Q4: Why is accuracy alone insufficient for evaluating an IDS?

**A:** Because network traffic is heavily imbalanced — typically 95%+ is normal. A model that blindly classifies everything as "normal" would achieve 95% accuracy but miss every attack. That's useless for security.

In my project, I focused on precision, recall, and F1 score. Recall is especially critical because a false negative means a real attack goes undetected, potentially leading to a breach. However, very low precision creates alert fatigue — if analysts get 100 false alarms for every real alert, they start ignoring alerts entirely. The F1 score balances both, and I also used ROC-AUC to evaluate the model's ability to rank suspicious flows higher than normal ones regardless of the threshold.

### Q5: How do you handle false positives?

**A:** False positives are inevitable — legitimate traffic like backup jobs, software updates, or database migrations can trigger anomaly detections. I handle them through several mechanisms:

First, the hybrid approach helps — a flow that triggers an anomaly but matches no rules gets a lower combined score than one flagged by both. Second, the dashboard allows analysts to mark alerts as FALSE_POSITIVE, which helps identify patterns for rule tuning. Third, the anomaly baseline can be updated with more representative normal traffic data. Fourth, rule thresholds are configurable — if IDS-006 generates too many false positives for high-bandwidth legitimate services, the bytes_per_second threshold can be raised.

In a production SOC, you'd also add contextual enrichment — known backup servers, scheduled maintenance windows, asset criticality — to automatically suppress expected patterns.

### Q6: What features did you engineer and why are they relevant?

**A:** I extract 15 features from each flow record. The most important for detection are:

- **connection_rate** (connections per second) — high rates indicate scanning or DDoS
- **failure_ratio** (failed/total connections) — high ratios suggest brute force
- **syn_ratio** (SYN packets / total packets) — high ratios indicate SYN floods
- **bytes_per_second** — extremely high values suggest data exfiltration or DDoS
- **packets_per_second** — flood indicators
- **average_packet_size** — protocol anomalies (e.g., many tiny packets = scanning)

Each feature is calculated with safe division to handle zero-duration flows. I also validate inputs — checking port ranges (0-65535), required fields, and data types before processing.

### Q7: Explain your alert correlation logic.

**A:** Instead of generating 100 separate alerts for the same source IP doing the same thing, I group related alerts. The correlator looks at three dimensions: same source IP, same alert type, and within a configurable time window (default 60 seconds).

When multiple alerts match these criteria, they're combined into a single incident with a count, first/last seen timestamps, and the highest severity from the group. This reduces the alert volume analysts see and helps them understand the scope of an event — "192.0.2.15 triggered High Connection Rate 47 times in 60 seconds" is more actionable than 47 individual alerts.

### Q8: How would you deploy this in a real network?

**A:** In production, I'd replace the synthetic traffic generator with real traffic ingestion — either Zeek processing PCAPs into flow logs, or consuming VPC flow logs in a cloud environment. The flows would be streamed through Kafka or a message queue into the detection pipeline. I'd use PostgreSQL instead of SQLite for scalability, add proper authentication (OAuth2/SAML) for the dashboard, implement role-based access control, and add threat intelligence enrichment to correlate source IPs against known malicious indicators.

I'd also containerize everything with Docker, add monitoring for the IDS itself (is it keeping up with traffic volume?), and implement model drift detection to know when the ML model needs retraining.

### Q9: What is the MITRE ATT&CK framework and how does it relate to your project?

**A:** MITRE ATT&CK is a knowledge base of adversary tactics, techniques, and procedures (TTPs) based on real-world observations. It provides a common language for describing attack behavior. In my project, the detection patterns can be loosely mapped to ATT&CK techniques — for example, multi-port probing aligns with T1046 (Network Service Discovery), and repeated failed connections align with T1110 (Brute Force).

However, I'm careful to note that a statistical anomaly doesn't automatically prove a specific attack technique. Proper ATT&CK mapping requires additional evidence and context. In a SOC, ATT&CK mapping helps with detection coverage analysis — "do we have detections for Initial Access tactics?" — and threat hunting — "show me all alerts potentially related to Lateral Movement."

### Q10: What would you improve in this project?

**A:** Three main areas:

**Detection quality:** I'd add behavioral baselines per source IP rather than global baselines, implement User/Entity Behavior Analytics (UEBA) to detect compromised accounts, and integrate threat intelligence feeds to enrich alerts with IP reputation data.

**Infrastructure:** I'd add real-time PCAP ingestion through Zeek, stream processing with Kafka, PostgreSQL for the database, and containerization with Docker. I'd also implement proper SIEM integration so alerts feed into a centralized security platform.

**ML improvements:** I'd experiment with XGBoost for better performance, implement online learning so the model adapts to evolving traffic patterns, add feature importance explanations to each alert, and monitor for concept drift to know when retraining is needed.

---

## Future Improvements

### Detection
- [ ] PCAP ingestion with Zeek/Suricata
- [ ] Per-source-IP behavioral baselines
- [ ] User/Entity Behavior Analytics (UEBA)
- [ ] Threat intelligence feed integration
- [ ] DNS tunneling detection
- [ ] Encrypted traffic analysis (JA3/JA4 fingerprinting)

### Infrastructure
- [ ] PostgreSQL for production scalability
- [ ] Kafka/Redis for stream processing
- [ ] Docker containerization
- [ ] Kubernetes deployment
- [ ] Centralized logging (ELK stack)
- [ ] SIEM integration (Splunk/Elastic SIEM)

### ML & Analytics
- [ ] XGBoost/LightGBM models
- [ ] Online learning for adaptive detection
- [ ] Feature importance in alert explanations
- [ ] Model drift monitoring
- [ ] Automated model retraining pipeline

### Dashboard
- [ ] Role-based access control (RBAC)
- [ ] OAuth2/SAML authentication
- [ ] Custom alert notification rules
- [ ] PDF incident report generation
- [ ] Dark/light theme toggle
- [ ] Mobile-responsive design
