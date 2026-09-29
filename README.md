# 🛡️ Network Intrusion Detection System (IDS) Simulation

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Defensive](https://img.shields.io/badge/Security-Defensive%20Only-brightgreen.svg)](#ethical-disclaimer)

> **A complete, industry-oriented defensive cybersecurity project** featuring synthetic traffic generation, signature-based and anomaly-based detection, hybrid risk scoring, alert correlation, SOC analytics, and optional machine learning — all running safely on localhost with synthetic data.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Objectives](#objectives)
- [Cybersecurity Relevance](#cybersecurity-relevance)
- [IDS Concepts](#ids-concepts)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Synthetic Dataset](#synthetic-dataset)
- [Traffic Simulator](#traffic-simulator)
- [Feature Engineering](#feature-engineering)
- [Signature-Based Detection](#signature-based-detection)
- [Anomaly Detection](#anomaly-detection)
- [Machine Learning](#machine-learning)
- [Hybrid Detection](#hybrid-detection)
- [Risk Scoring](#risk-scoring)
- [Alert Generation](#alert-generation)
- [Alert Correlation](#alert-correlation)
- [SOC Dashboard](#soc-dashboard)
- [Incident Investigation](#incident-investigation)
- [API Documentation](#api-documentation)
- [Installation](#installation)
- [Usage](#usage)
- [Testing](#testing)
- [Security Considerations](#security-considerations)
- [Results](#results)
- [False Positives & False Negatives](#false-positives--false-negatives)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [SIEM Integration](#siem-integration)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)
- [Screenshots](#screenshots)
- [Learning Outcomes](#learning-outcomes)
- [Ethical Disclaimer](#ethical-disclaimer)
- [Author](#author)

---

## Overview

This project simulates a **Network-Based Hybrid Intrusion Detection System (NIDS)** that processes synthetic network flow records through a multi-layered detection pipeline:

```
Synthetic Traffic Generator
          ↓
     Flow Collector
          ↓
    Feature Extractor
          ↓
 ┌────────┼──────────┐
 ↓        ↓          ↓
Rules   Anomaly      ML
Engine  Detector    Model
 └────────┼──────────┘
          ↓
     Risk Engine
          ↓
     Alert Engine
          ↓
    Security Database
          ↓
      SOC Dashboard
          ↓
        Analyst
```

It mirrors how modern enterprise tools (Suricata/Snort + analytics platforms) work in production SOC environments — but runs entirely on localhost with safe, synthetic data.

---

## Problem Statement

Organizations face increasing volumes of network traffic and sophisticated cyber threats. Security Operations Centers (SOCs) need automated systems to:

- Monitor thousands of network flows per second
- Detect known attack patterns (signature detection)
- Identify unknown/zero-day anomalies (anomaly detection)
- Prioritize alerts by risk severity
- Reduce analyst fatigue from false positives
- Enable efficient investigation workflows

This project demonstrates these capabilities in a safe, educational simulation.

---

## Objectives

1. ✅ Generate and load synthetic network traffic
2. ✅ Monitor network-flow records in near real-time
3. ✅ Analyze source/destination information, protocols, and ports
4. ✅ Detect suspicious traffic patterns using rule-based detection
5. ✅ Apply anomaly-based detection using statistical methods
6. ✅ Optionally use machine learning (Random Forest, Logistic Regression, Isolation Forest)
7. ✅ Generate intrusion alerts with severity levels and risk scores
8. ✅ Correlate related alerts into incidents
9. ✅ Store all security events in a structured database
10. ✅ Display a professional SOC dashboard with traffic analytics
11. ✅ Support SOC-style investigation with analyst notes and status tracking
12. ✅ Generate incident reports

---

## Cybersecurity Relevance

### Industry Use Cases

| Organization | IDS Application |
|-------------|----------------|
| **SOC Teams** | Real-time alert triage, threat hunting, incident response |
| **Banks** | Fraud detection, PCI DSS compliance monitoring |
| **Cloud Providers** | VPC flow log analysis, east-west traffic monitoring |
| **Enterprises** | Network segmentation validation, insider threat detection |
| **Government** | Critical infrastructure protection, APT detection |
| **Universities** | Research network monitoring, academic security |
| **MSSPs** | Multi-tenant security monitoring as a service |

### Relevant Roles

- **SOC Analyst (Tier 1/2)** — Alert triage, investigation, escalation
- **Network Security Analyst** — Traffic analysis, firewall rule tuning
- **Cybersecurity Analyst** — Risk assessment, vulnerability management
- **Security Engineer** — IDS/IPS deployment, rule authoring
- **Incident Response Analyst** — Forensics, containment, remediation
- **Threat Detection Engineer** — Detection logic, SIEM integration

---

## IDS Concepts

### What is an IDS?

**Simple:** An IDS is a security guard for your network — it watches all the traffic flowing through and raises an alarm if something looks suspicious.

**Technical:** An Intrusion Detection System (IDS) is a network security appliance or software that monitors network traffic or system activities for malicious patterns, policy violations, or anomalies. It generates alerts for security analysts to investigate.

### Key Terminology

| Term | Definition |
|------|-----------|
| **Network Traffic** | Data flowing between devices on a network |
| **Network Flow** | A summary of a single connection (src/dst IP, ports, bytes, duration) |
| **Packet** | The smallest unit of data transmitted over a network |
| **Security Event** | Any observable occurrence relevant to security |
| **Alert** | A notification generated when suspicious activity is detected |
| **Incident** | A collection of related alerts requiring coordinated investigation |

### IDS vs IPS

| Feature | IDS | IPS |
|---------|-----|-----|
| **Mode** | Passive monitoring | Active prevention |
| **Action** | Detect & alert | Detect, alert & block |
| **Risk** | No traffic disruption | May block legitimate traffic |
| **This Project** | ✅ IDS (detect only) | ❌ Not implemented |

> **Why IDS?** This project intentionally simulates detection-only. An IPS would require integration with actual network infrastructure and carries the risk of blocking legitimate traffic.

### Detection Methods

| Method | Signature-Based | Anomaly-Based | Hybrid |
|--------|----------------|---------------|--------|
| **Approach** | Match known patterns | Detect deviations from baseline | Both combined |
| **Strengths** | Low false positives, explainable | Catches unknown threats | Comprehensive coverage |
| **Weaknesses** | Misses novel attacks | Higher false positives | More complex |
| **This Project** | ✅ 8 rules | ✅ Z-score based | ✅ Weighted combination |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   TRAFFIC LAYER                         │
│  ┌──────────────────┐  ┌──────────────────────────┐    │
│  │ Dataset Generator │  │  Real-Time Simulator      │    │
│  │ (5000+ records)   │  │  (continuous JSON flows)  │    │
│  └────────┬─────────┘  └──────────┬───────────────┘    │
│           └──────────┬────────────┘                     │
│                      ↓                                  │
│  ┌──────────────────────────────────────────────┐      │
│  │            Feature Extractor                  │      │
│  │  packet_rate | byte_rate | failure_ratio      │      │
│  │  syn_ratio | connection_rate | ...            │      │
│  └──────────────────┬───────────────────────────┘      │
│                     ↓                                   │
│  ┌────────────┬─────┴──────────┬───────────────┐       │
│  │   Rule     │   Anomaly      │   ML Model    │       │
│  │   Engine   │   Detector     │   (Optional)  │       │
│  │ 8 rules    │   Z-score      │   RF/LR/IF    │       │
│  └─────┬──────┴───────┬────────┴───────┬───────┘       │
│        └──────────────┼────────────────┘                │
│                       ↓                                 │
│  ┌──────────────────────────────────────────────┐      │
│  │          Hybrid Risk Engine                   │      │
│  │  Rule (40%) + Anomaly (30%) + ML (30%)        │      │
│  │  → Score 0–100 → Classification               │      │
│  └──────────────────┬───────────────────────────┘      │
│                     ↓                                   │
│  ┌──────────────────────────────────────────────┐      │
│  │          Alert & Correlation Engine            │      │
│  │  Generate alerts → Group by source/type/time  │      │
│  └──────────────────┬───────────────────────────┘      │
│                     ↓                                   │
│  ┌──────────────────────────────────────────────┐      │
│  │          SQLite Database                       │      │
│  │  flows | alerts | rules | notes | ml_results  │      │
│  └──────────────────┬───────────────────────────┘      │
│                     ↓                                   │
│  ┌──────────────────────────────────────────────┐      │
│  │   FastAPI Backend (REST + SSE)                 │      │
│  └──────────────────┬───────────────────────────┘      │
│                     ↓                                   │
│  ┌──────────────────────────────────────────────┐      │
│  │   React SOC Dashboard                         │      │
│  │   Charts | Alerts | Investigation | Rules     │      │
│  └──────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────┘
```

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.10+, FastAPI, Uvicorn |
| **Frontend** | React 18, Recharts, Axios, React Router |
| **Database** | SQLite |
| **ML** | scikit-learn (Random Forest, Logistic Regression, Isolation Forest) |
| **Real-time** | Server-Sent Events (SSE) |
| **Testing** | pytest, httpx |

---

## Synthetic Dataset

The dataset generator creates **5,000+ flow records** with realistic patterns:

### Normal Scenarios (~70%)
| Scenario | Ports | Protocol | Characteristics |
|----------|-------|----------|----------------|
| `NORMAL_WEB` | 80, 443 | TCP | Moderate traffic, low failure |
| `NORMAL_DNS` | 53 | UDP/TCP | Small packets, short duration |
| `NORMAL_SSH` | 22 | TCP | Long sessions, few failures |
| `NORMAL_EMAIL` | 25, 587, 993 | TCP | Moderate size transfers |
| `NORMAL_DATABASE` | 3306, 5432 | TCP | High packet count, stable |

### Suspicious Scenarios (~30%)
| Scenario | Indicator | Detection |
|----------|-----------|-----------|
| `HIGH_CONNECTION_RATE` | 100-500 connections in <0.1s | Rule IDS-001 |
| `REPEATED_FAILED_CONNECTIONS` | >50% failure ratio | Rule IDS-002 |
| `MULTI_PORT_PROBING_PATTERN` | Many unique destination ports | Rule IDS-003 |
| `SYN_HEAVY_PATTERN` | >80% SYN ratio | Rule IDS-004 |
| `UNUSUAL_PORT_ACTIVITY` | Ports 4444, 8888, 31337 | Rule IDS-005 |
| `HIGH_TRAFFIC_VOLUME` | >1MB/s transfer rate | Rule IDS-006 |

> **Safety:** All IPs use RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). No real network traffic is generated.

Generate the dataset:
```bash
python simulator/generate_dataset.py --count 5000 --output data/network_traffic.csv
```

---

## Feature Engineering

Each flow record is transformed into **15 engineered features**:

| Feature | Formula | Security Relevance |
|---------|---------|-------------------|
| `bytes_per_second` | byte_count / duration | Data exfiltration, DDoS |
| `packets_per_second` | packet_count / duration | Flood attacks |
| `average_packet_size` | byte_count / packet_count | Protocol anomalies |
| `failure_ratio` | failed / total connections | Brute force, scanning |
| `syn_ratio` | syn_count / packet_count | SYN flood attacks |
| `connection_rate` | connections / duration | Port scanning, DoS |

---

## Signature-Based Detection

8 configurable detection rules:

| Rule ID | Name | Threshold | Severity |
|---------|------|-----------|----------|
| IDS-001 | High Connection Rate | >50/sec | HIGH |
| IDS-002 | Repeated Failed Connections | >50% fail + >10 failed | HIGH |
| IDS-003 | Multi-Port Activity | >15 unique ports | MEDIUM |
| IDS-004 | SYN-Heavy Pattern | >80% SYN + >100 SYNs | HIGH |
| IDS-005 | Unusual Port Activity | Ports 4444/8888/31337 | MEDIUM |
| IDS-006 | High Traffic Volume | >1MB/s | HIGH |
| IDS-007 | Connection Burst | >100 in <2s | MEDIUM |
| IDS-008 | RST Flood | >50 RSTs + >50% ratio | HIGH |

---

## Anomaly Detection

Statistical anomaly detection using **Z-score analysis**:

```
Normal Baseline (from training data)
          ↓
  Observe New Flow
          ↓
  Compare Against Baseline
          ↓
  Calculate Z-score per metric
          ↓
  Combine into Anomaly Score (0–100)
```

Metrics monitored: packet rate, byte rate, connection rate, failure ratio, SYN ratio, average packet size.

---

## Machine Learning

Three models trained on the synthetic dataset:

| Model | Type | Best For |
|-------|------|----------|
| **Random Forest** | Supervised | Best overall F1 score |
| **Logistic Regression** | Supervised | Fast, interpretable |
| **Isolation Forest** | Unsupervised | Novel anomaly detection |

Train models:
```bash
python ml/train_model.py --data-path data/network_traffic.csv --output-dir models/
```

---

## Risk Scoring

Hybrid weighted scoring:

| Component | Weight (with ML) | Weight (without ML) |
|-----------|------------------|---------------------|
| Rule-Based | 40% | 60% |
| Anomaly | 30% | 40% |
| ML | 30% | 0% |

### Classification Scale

| Score | Classification | Severity |
|-------|---------------|----------|
| 0–20 | NORMAL | INFO |
| 21–40 | LOW RISK | LOW |
| 41–60 | SUSPICIOUS | MEDIUM |
| 61–80 | HIGH RISK | HIGH |
| 81–100 | CRITICAL INVESTIGATION | CRITICAL |

---

## Alert Generation

Alerts are generated when risk score > 20:

```json
{
  "alert_id": "ALT-10021",
  "alert_type": "High Connection Rate",
  "severity": "HIGH",
  "source_ip": "192.0.2.15",
  "destination_ip": "198.51.100.20",
  "risk_score": 76,
  "status": "NEW",
  "investigation_steps": [
    "Review historical activity for source IP",
    "Check for corresponding endpoint alerts",
    "Block source IP on firewall pending investigation"
  ]
}
```

---

## SOC Dashboard

Professional dark-themed dashboard with:

- **6 Summary Cards** — Total flows, normal/suspicious counts, open/critical alerts, avg risk
- **Traffic Over Time** — Area chart (normal vs suspicious)
- **Alerts by Severity** — Bar chart with severity colors
- **Protocol Distribution** — Pie chart
- **Top Source IPs** — Horizontal bar chart
- **Risk Score Distribution** — Histogram
- **Recent Alerts Table** — Clickable rows for investigation
- **Real-time updates** via Server-Sent Events

---

## API Documentation

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/flows` | Submit flow through IDS pipeline |
| `GET` | `/api/flows` | List flows with filters |
| `GET` | `/api/flows/{id}` | Get flow details |
| `GET` | `/api/alerts` | List alerts with filters |
| `GET` | `/api/alerts/{id}` | Get alert details + notes |
| `PUT` | `/api/alerts/{id}/status` | Update alert status |
| `POST` | `/api/alerts/{id}/notes` | Add analyst note |
| `GET` | `/api/dashboard/stats` | Dashboard summary |
| `GET` | `/api/dashboard/traffic` | Traffic timeline |
| `GET` | `/api/rules` | List detection rules |
| `PUT` | `/api/rules/{id}` | Update rule threshold |
| `GET` | `/api/events/stream` | SSE real-time stream |
| `GET` | `/api/health` | Health check |

Interactive API docs: `http://localhost:8000/docs`

---

## Installation

### Prerequisites
- Python 3.10+
- Node.js 16+ & npm

### Step 1: Clone Repository
```bash
git clone https://github.com/YOUR_USERNAME/Network-Intrusion-Detection-System-Simulation.git
cd Network-Intrusion-Detection-System-Simulation
```

### Step 2: Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Install Frontend Dependencies
```bash
cd frontend
npm install
cd ..
```

### Step 4: Configure Environment
```bash
cp .env.example .env
# Edit .env if needed
```

---

## Usage

### Quick Start (One Command)
```bash
python run.py
```
This generates synthetic data and starts the backend server.

### Full Setup with ML
```bash
python run.py --train
```

### Step-by-Step

**Terminal 1 — Backend:**
```bash
python run.py --train
```

**Terminal 2 — Frontend:**
```bash
cd frontend
npm start
```

**Terminal 3 — Traffic Simulator:**
```bash
python simulator/traffic_simulator.py --mode mixed --speed fast --api-url http://localhost:8000
```

**Open Dashboard:** `http://localhost:3000`

### Simulation Walkthrough

1. **Normal Flow** → HTTPS, port 443, normal rate → Classified as NORMAL
2. **Suspicious Flow** → High connections, many failures → Classified as SUSPICIOUS
3. **Alert Triggered** → Rule IDS-001 matched → Alert appears on dashboard
4. **Investigation** → Click alert → View details, matched rules, anomaly score
5. **Triage** → Update status: NEW → INVESTIGATING
6. **Document** → Add analyst notes
7. **Resolve** → Mark as RESOLVED or FALSE_POSITIVE

---

## Testing

Run all tests:
```bash
pytest tests/ -v
```

### Test Coverage

| Module | Tests | Coverage |
|--------|-------|---------|
| Feature Extractor | 10 | Normal flows, edge cases, validation |
| Rule Engine | 10 | Each rule + disable/threshold |
| Anomaly Detector | 5 | Scoring, baseline, Z-score |
| Risk Engine | 5 | Classifications, weights |
| Alert Engine | 5 | Generation, format, steps |
| Correlation | 3 | Grouping, time window |
| API | 7 | All endpoints |
| ML | 3 | Prediction format |
| **Total** | **48** | |

---

## Security Considerations

- 🔒 **Synthetic data only** — No real network traffic captured
- 🔒 **No payload storage** — Only flow metadata analyzed
- 🔒 **Environment variables** — Secrets stored in `.env`
- 🔒 **Input validation** — Pydantic models on all endpoints
- 🔒 **Rate limiting** — Recommended for production
- 🔒 **Authentication** — Recommended for production deployment
- 🔒 **Audit logging** — All status changes tracked
- 🔒 **Least privilege** — Read-only dashboard, write-only investigation

---

## False Positives & False Negatives

| Type | Definition | Example | Impact |
|------|-----------|---------|--------|
| **False Positive** | Legitimate traffic flagged as suspicious | Backup system generating high traffic | SOC fatigue, wasted time |
| **False Negative** | Malicious traffic missed | Slow, low-volume data exfiltration | Security breach |

### Mitigation Strategies
- Better baselines from longer observation periods
- Multiple detection methods (hybrid approach)
- Threshold tuning based on analyst feedback
- Contextual enrichment (asset tags, known hosts)

---

## MITRE ATT&CK Mapping

Network IDS alerts can be mapped to ATT&CK tactics when sufficient evidence exists:

| Detection | Possible Tactic | Possible Technique |
|-----------|----------------|-------------------|
| Port Scan Pattern | Reconnaissance | T1046 - Network Service Discovery |
| Failed Connections | Credential Access | T1110 - Brute Force |
| SYN Flood | Impact | T1498 - Network Denial of Service |
| Unusual Ports | Command and Control | T1571 - Non-Standard Port |
| High Data Volume | Exfiltration | T1048 - Exfiltration Over Alternative Protocol |

> **Note:** A statistical anomaly does not automatically prove a specific attack. ATT&CK mapping requires additional evidence and context.

---

## SIEM Integration

IDS alerts can be forwarded to a SIEM via JSON:

```json
{
  "alert_id": "ALT-1001",
  "source_ip": "192.0.2.15",
  "destination_ip": "198.51.100.20",
  "severity": "HIGH",
  "rule": "High Connection Rate",
  "risk_score": 78,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

```
IDS → JSON Alert → Log Forwarder/API → SIEM → Correlation → SOC Analyst
```

---

## Limitations

- Uses synthetic data, not real network traffic
- Simplified rule thresholds (not production-calibrated)
- SQLite (not suitable for high-volume production)
- No packet-level deep inspection
- No real-time PCAP ingestion
- Single-user dashboard (no RBAC)

---

## Future Improvements

- 📡 PCAP ingestion with authorized captures
- 🔄 Real-time flow ingestion via Zeek/Suricata
- 📊 SIEM integration (Splunk, ELK)
- 🧠 Advanced ML (XGBoost, deep learning)
- 👤 User/Entity Behavior Analytics (UEBA)
- ☁️ Cloud IDS monitoring (VPC flow logs)
- 🐳 Docker containerization
- 📈 Model drift monitoring
- 🔍 Threat intelligence enrichment

---

## Learning Outcomes

Through this project, I learned:

- **Network Security** — Flow analysis, protocol behavior, port scanning patterns
- **Intrusion Detection** — Signature vs anomaly vs ML detection
- **SOC Operations** — Alert triage, investigation workflows, incident management
- **Feature Engineering** — Extracting security-relevant features from raw data
- **Machine Learning** — Supervised/unsupervised classification, evaluation metrics
- **Full-Stack Development** — FastAPI + React + SQLite
- **Security Analytics** — Risk scoring, alert correlation, false positive management
- **Secure Coding** — Input validation, error handling, environment variables

---

## Ethical Disclaimer

> **⚠️ This project is designed exclusively for defensive cybersecurity education.**
>
> - All suspicious network behavior is represented using **synthetic data records**
> - No real attack traffic is generated, captured, or replayed
> - All IP addresses use **RFC 5737 documentation ranges** (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
> - This system does **NOT** scan, probe, exploit, disrupt, or attack any external systems
> - The IDS operates in **detection-only mode** — it does not block or modify traffic
>
> This project demonstrates defensive security concepts for educational purposes only.

---

## Author

**Rohit Singh**
IIT Delhi | Cybersecurity Course Project

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
