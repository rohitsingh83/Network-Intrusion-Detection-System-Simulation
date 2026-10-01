# AegisFlow — Network Intrusion Detection System (IDS) Simulation

[![Live SOC Demo](https://img.shields.io/badge/🛡️_Live_Demo-GitHub_Pages-22c55e?style=for-the-badge&logo=github)](https://rohitsingh83.github.io/Network-Intrusion-Detection-System-Simulation/)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-15-black?style=flat-square&logo=next.js)](https://nextjs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?style=flat-square&logo=typescript)](https://typescriptlang.org)
[![Tests](https://img.shields.io/badge/Tests-78%20passing-22c55e?style=flat-square&logo=pytest)](./tests/)
[![Defensive](https://img.shields.io/badge/Security-Defensive_Only-22c55e?style=flat-square)](#ethical-disclaimer)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

> **🌐 LIVE INTERACTIVE SOC DASHBOARD →  
> [https://rohitsingh83.github.io/Network-Intrusion-Detection-System-Simulation/](https://rohitsingh83.github.io/Network-Intrusion-Detection-System-Simulation/)**
>
> Runs 100% in your browser — no backend required.  
> Real-time synthetic traffic, rule-based detection, anomaly scoring, and alert triage.

---

## Table of Contents

- [Overview](#overview)
- [Live Demo](#live-demo)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Features](#features)
- [Quick Start (Local)](#quick-start-local)
- [Project Structure](#project-structure)
- [Detection Engines](#detection-engines)
- [API Reference](#api-reference)
- [Tests](#tests)
- [Deploy to GitHub Pages](#deploy-to-github-pages)
- [Docker](#docker)
- [Ethical Disclaimer](#ethical-disclaimer)
- [Interview Q&A](#interview-qa)

---

## Overview

AegisFlow is a **production-grade, industry-oriented Network Intrusion Detection System simulation** built as a cybersecurity course project. It demonstrates the full stack of a real SOC environment:

- **Synthetic traffic generation** — 5,000+ RFC 5737 flow records across 11 scenario types
- **Hybrid detection** — signature rules + statistical anomaly detection + optional Random Forest ML
- **Real-time SOC dashboard** — Next.js 15 + Tailwind + Shadcn UI with live flow feeds via SSE
- **Full alert lifecycle** — severity triage, analyst notes, status transitions, incident correlation
- **Production hardening** — rate limiting, security headers, structured logging, Docker, health checks

All traffic uses **RFC 5737 documentation IP ranges only** (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`). No real networks are scanned or probed.

---

## Live Demo

**URL:** https://rohitsingh83.github.io/Network-Intrusion-Detection-System-Simulation/

| Page | Description |
|------|-------------|
| `/` | SOC Command Center — live metric cards, traffic charts, severity distribution |
| `/alerts` | Alert management table with severity/status filters |
| `/alerts/[id]` | Alert investigation — rule breakdown, anomaly scores, analyst notes |
| `/incidents` | Incident correlation view |
| `/simulator` | Backend health + simulator controls |

The GitHub Pages version runs a **full in-browser IDS simulation**:
- Seeded RNG generates synthetic flows every 1.5 seconds
- 8 detection rules classify traffic (port scan, SYN flood, brute force, etc.)
- Alerts are generated, stored in memory, and displayed in real-time
- Alert status + analyst notes persist for the duration of the browser session

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    AEGISFLOW IDS ARCHITECTURE                    │
├──────────────────┬──────────────────────────────────────────────┤
│  Traffic Source  │  Synthetic CSV / Real-time Simulator / SSE   │
├──────────────────┼──────────────────────────────────────────────┤
│  Feature         │  feature_extractor.py                         │
│  Extraction      │  IP validation, protocol check, 14 features   │
├──────────────────┼──────────────────────────────────────────────┤
│  Detection       │  rule_engine.py    → 8 signature rules        │
│  Engines         │  anomaly_detector.py → Z-score baseline       │
│                  │  ml/predict.py     → Random Forest (optional) │
├──────────────────┼──────────────────────────────────────────────┤
│  Risk Scoring    │  risk_engine.py → weighted 0–100 score        │
├──────────────────┼──────────────────────────────────────────────┤
│  Alert Engine    │  alert_engine.py → severity, playbook actions │
│  Correlation     │  correlation.py  → group related alerts       │
├──────────────────┼──────────────────────────────────────────────┤
│  Backend API     │  FastAPI + SQLite + SSE stream                │
├──────────────────┼──────────────────────────────────────────────┤
│  SOC Dashboard   │  Next.js 15 + TypeScript + Shadcn UI          │
│  (Frontend)      │  TanStack Query + Recharts + Sonner           │
└──────────────────┴──────────────────────────────────────────────┘
```

---

## Technology Stack

### Backend
| Component | Technology |
|-----------|------------|
| API Framework | FastAPI 0.104+ |
| Language | Python 3.10+ |
| Database | SQLite (via custom DatabaseManager) |
| ML | scikit-learn (Random Forest) |
| Config | Pydantic v2 BaseSettings |
| Runtime | Uvicorn with ASGI lifespan |

### Frontend
| Component | Technology |
|-----------|------------|
| Framework | Next.js 15 (App Router, static export) |
| Language | TypeScript 5 (strict mode, zero `any`) |
| Styling | Tailwind CSS v3.4 + Shadcn UI |
| Charts | Recharts |
| Data | TanStack Query v5 |
| Notifications | Sonner |
| Icons | Lucide React |

### Infrastructure
| Component | Technology |
|-----------|------------|
| Container | Docker (multi-stage build) |
| Orchestration | Docker Compose |
| CI/CD | GitHub Actions → GitHub Pages |
| Security | CORS, rate limiting, security headers |

---

## Features

### Detection Capabilities
- **8 Signature Rules**: Port scan, SYN flood, brute force SSH, high connection rate, high traffic volume, unusual ports, failed connection threshold, anomalous packet rate
- **Statistical Anomaly Detection**: Z-score baseline from historical flows, 5 features monitored
- **Optional ML**: Random Forest trained on 5,000 synthetic records, lazy-loaded
- **Hybrid Risk Scoring**: Weighted combination (rules 40% + anomaly 30% + ML 30%)

### Alert System
- **5 Severity Levels**: INFO / LOW / MEDIUM / HIGH / CRITICAL
- **4 Status States**: NEW → INVESTIGATING → RESOLVED / FALSE_POSITIVE
- **Alert Correlation**: Groups related alerts into incidents (same source IP, same 10-min window)
- **Playbook Actions**: Recommended SOC response steps per alert type
- **Analyst Notes**: Thread-style notes with analyst name, action taken, timestamp

### Dashboard
- **Live Flow Feed**: Real-time table updated via SSE (or browser simulation on GitHub Pages)
- **6 Metric Cards**: Total flows, normal, suspicious, open alerts, critical, avg risk score
- **Traffic Velocity Chart**: Area chart with gradient — total vs suspicious flows
- **Severity Donut**: Distribution of alert severities
- **Protocol Bar Chart**: TCP / UDP / ICMP breakdown
- **Top Source IPs**: Ranked suspicious sources

### Production Features
- **Healthcheck**: `GET /api/health` → version, uptime, DB status, ML readiness
- **Rate Limiting**: Sliding-window per-IP (600 req/min, SSE streams exempt)
- **Security Headers**: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- **Structured Logging**: JSON-compatible backend logs
- **Environment Validation**: Pydantic BaseSettings with type-checked config
- **Docker**: Multi-stage build, unprivileged user (UID 10001), volume mounts

---

## Quick Start (Local)

### Prerequisites
- Python 3.10+ (`python --version`)
- Node.js 18+ (`node --version`)
- Git

### 1. Clone & Setup
```bash
git clone https://github.com/rohitsingh83/Network-Intrusion-Detection-System-Simulation.git
cd Network-Intrusion-Detection-System-Simulation
pip install -r requirements.txt
```

### 2. Generate Dataset & Train Model
```bash
python simulator/generate_dataset.py   # creates data/network_traffic.csv (5000 records)
python ml/train_model.py               # trains Random Forest, saves models/ids_model.joblib
```

### 3. Start Backend
```bash
python run.py
# OR directly:
python -m uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Start Frontend (Dev Mode)
```bash
cd frontend
npm install
npm run dev
# Visit http://localhost:3000
```

### 5. Run Traffic Simulator (Optional)
```bash
python simulator/traffic_simulator.py --speed normal --duration 60
```

### Access
| Service | URL |
|---------|-----|
| SOC Dashboard | http://localhost:3000 |
| FastAPI (Backend) | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |
| Health Check | http://localhost:8000/api/health |

---

## Project Structure

```
Network-IDS-Simulation/
├── backend/                   FastAPI backend
│   ├── app.py                 Main app (middleware, routing, SSE)
│   ├── config.py              Pydantic BaseSettings (env validation)
│   ├── database.py            SQLite manager (flows, alerts, stats)
│   └── routes/
│       ├── flows.py           POST /api/flows (analyze a flow)
│       ├── alerts.py          GET/PUT/POST /api/alerts/*
│       ├── dashboard.py       GET /api/dashboard/*
│       ├── rules.py           GET /api/rules
│       └── sse.py             GET /api/events (SSE stream)
│
├── ids/                       Detection engines
│   ├── feature_extractor.py   14-feature extraction + validation
│   ├── rule_engine.py         8 signature-based rules
│   ├── anomaly_detector.py    Z-score baseline detector
│   ├── risk_engine.py         Hybrid 0–100 risk scorer
│   ├── alert_engine.py        Alert generator + playbooks
│   └── correlation.py         Alert → incident grouping
│
├── ml/
│   ├── train_model.py         Random Forest trainer
│   ├── predict.py             Lazy-loaded predictor
│   └── evaluate.py            Model evaluation metrics
│
├── simulator/
│   ├── generate_dataset.py    5000-record CSV generator
│   └── traffic_simulator.py   Real-time flow streamer CLI
│
├── frontend/                  Next.js 15 SOC Dashboard
│   ├── app/                   App Router pages
│   │   ├── page.tsx           Dashboard
│   │   ├── alerts/page.tsx    Alert list
│   │   ├── alerts/[id]/       Alert investigation
│   │   ├── incidents/         Incident list
│   │   └── simulator/         Simulator controls
│   ├── components/
│   │   ├── layout/sidebar.tsx  Navigation sidebar
│   │   ├── dashboard/          Metric cards, badges
│   │   └── ui/                 Shadcn UI primitives
│   ├── hooks/
│   │   ├── use-live-telemetry.ts  SSE / mock subscriber
│   │   └── use-alerts.ts          Alert queries + mutations
│   ├── lib/
│   │   ├── api-client.ts       Dual-mode API (real / mock)
│   │   └── mock-engine.ts      In-browser IDS simulation
│   └── types/index.ts          Shared TypeScript types
│
├── tests/                     pytest test suite (78 tests)
├── data/                      SQLite DB + CSV dataset
├── models/                    Trained joblib model
├── scripts/
│   ├── deploy-gh-pages.ps1    Windows deploy script
│   └── deploy-gh-pages.sh     Linux/macOS deploy script
├── Dockerfile                 Multi-stage production build
├── docker-compose.yml         Backend + simulator services
└── run.py                     Master launch script
```

---

## Detection Engines

### Feature Extraction (`ids/feature_extractor.py`)
Extracts 14 features from raw network flow records:
- Rate features: packets/sec, bytes/sec, connections/sec
- Ratio features: failed connection ratio, RST ratio, SYN ratio
- Absolute counts: packet_count, byte_count, connection_count
- Metadata: protocol (one-hot), source/dest ports
- Validates RFC 5737 IPs and TCP/UDP/ICMP protocols

### Rule Engine (`ids/rule_engine.py`)
8 signature-based rules, each returns `(triggered: bool, confidence: float)`:

| Rule | Trigger Condition |
|------|-----------------|
| R001 Port Scan | conn_count > 50, failed_ratio > 0.7, unique_ports > 20 |
| R002 SYN Flood | syn_count > 200, duration < 1s |
| R003 Brute Force SSH | dst_port == 22, failed_conn > 10 |
| R004 High Conn Rate | connections/sec > 50 |
| R005 Unusual Port | port not in [80,443,22,53,3306,25,8080,110] |
| R006 High Volume | bytes/sec > 100,000 |
| R007 Failed Threshold | failed_connections > 20 |
| R008 Anomalous Packets | packet_rate > 3σ above baseline |

### Anomaly Detector (`ids/anomaly_detector.py`)
- Computes Z-scores for 5 features against a rolling baseline
- Baseline pre-computed from the synthetic CSV (cached to `data/baseline.json`)
- Anomaly score = `max(|z| for each feature)`; threshold = 3.0

### Risk Engine (`ids/risk_engine.py`)
```
risk_score = (
    rule_score    × 0.40  +
    anomaly_score × 0.30  +
    ml_score      × 0.30
) × 100  [0–100]
```

---

## API Reference

All endpoints available at `http://localhost:8000/api/`

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | System health, uptime, component status |
| POST | `/api/flows` | Analyze a single flow record |
| GET | `/api/flows` | List flows (filter by protocol, classification) |
| GET | `/api/alerts` | List alerts (filter by severity, status) |
| GET | `/api/alerts/{id}` | Get alert detail with notes |
| PUT | `/api/alerts/{id}/status` | Update alert status + analyst |
| POST | `/api/alerts/{id}/notes` | Add analyst note |
| GET | `/api/dashboard/stats` | Aggregate metrics |
| GET | `/api/dashboard/traffic` | Traffic timeline |
| GET | `/api/dashboard/protocols` | Protocol distribution |
| GET | `/api/dashboard/severity` | Severity distribution |
| GET | `/api/dashboard/ports` | Top destination ports |
| GET | `/api/dashboard/sources` | Top suspicious sources |
| GET | `/api/rules` | Active detection rules |
| GET | `/api/events` | SSE stream (new_flow, new_alert) |

Interactive docs: http://localhost:8000/docs

---

## Tests

```bash
python -m pytest tests/ -v
```

**78 tests / 78 passing** in ~1.7s:

| Test File | Tests | Coverage |
|-----------|-------|----------|
| test_feature_extractor.py | 10 | IP/protocol validation, feature extraction |
| test_rule_engine.py | 10 | All 8 rules, edge cases |
| test_anomaly_detector.py | 5 | Z-score, baseline, thresholds |
| test_risk_engine.py | 5 | Weighted scoring, edge cases |
| test_alert_engine.py | 5 | Severity mapping, playbooks |
| test_correlation.py | 3 | Incident grouping |
| test_ml.py | 3 | Lazy load, predict, shape |
| test_api.py | 7 | All API endpoints |
| test_30_scenarios.py | 30 | End-to-end scenario coverage |

---

## Deploy to GitHub Pages

### Automatic (Recommended)
The GitHub Actions workflow at `.github/workflows/deploy-pages.yml` auto-deploys on every push to `main`.

To enable it, push the workflow file with a token that has the `workflow` scope:
1. Go to GitHub → Settings → Developer Settings → Personal Access Tokens → Classic
2. Generate token with scopes: `repo` + `workflow`
3. Run: `git push https://<YOUR-TOKEN>@github.com/rohitsingh83/Network-Intrusion-Detection-System-Simulation.git main`

### Manual (Works Now — No Special Token Required)
```powershell
# Windows
.\scripts\deploy-gh-pages.ps1

# Linux / macOS
bash scripts/deploy-gh-pages.sh
```

The script:
1. Builds Next.js with `GITHUB_PAGES=true` (activates basePath + standalone mock engine)
2. Adds `.nojekyll` (so GitHub Pages serves `_next/` assets)
3. Force-pushes `frontend/out/` to the `gh-pages` branch

Live at: https://rohitsingh83.github.io/Network-Intrusion-Detection-System-Simulation/

---

## Docker

### Build & Run
```bash
docker-compose up --build
```

Services:
- `ids-backend` → FastAPI on port 8000
- `traffic-simulator` → streams synthetic flows (starts after backend is healthy)

### Manual Docker Build
```bash
docker build -t aegisflow-ids .
docker run -p 8000:8000 -v $(pwd)/data:/app/data aegisflow-ids
```

---

## Ethical Disclaimer

> **This is a DEFENSIVE cybersecurity project for educational purposes only.**
>
> - All IP addresses are RFC 5737 documentation ranges (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`)
> - No real network traffic is generated or captured
> - No real systems are scanned, probed, or exploited
> - All "attack patterns" are represented as synthetic data records only
> - This project complies with all applicable laws and ethical guidelines

---

## Interview Q&A

**Q: What is an IDS and how does it differ from an IPS?**  
An IDS (Intrusion Detection System) monitors network traffic and raises alerts when suspicious patterns are detected. An IPS (Intrusion Prevention System) goes further by actively blocking suspicious traffic. AegisFlow is a NIDS (Network-based IDS) that inspects flow metadata.

**Q: What is the difference between signature-based and anomaly-based detection?**  
Signature detection matches traffic against known attack patterns (like antivirus signatures). Anomaly detection establishes a baseline of "normal" behavior and flags statistical deviations. Both have tradeoffs: signatures miss zero-days; anomaly detection can produce false positives.

**Q: How does your hybrid risk scoring work?**  
We compute three independent scores: rule confidence (40% weight), Z-score anomaly magnitude (30%), and ML class probability (30%). The weighted sum gives a 0–100 risk score. This reduces false positives compared to any single method.

**Q: Why use Random Forest for network intrusion detection?**  
Random Forests handle the mixed continuous/categorical features in network flows well, are robust to outliers, and provide feature importance rankings. They are interpretable enough for SOC analysts and fast enough for near-real-time inference.

**Q: What is alert correlation and why is it important?**  
Alert correlation groups related alerts (same source IP within a 10-minute window) into an incident. Without correlation, a port scan generating 500 individual alerts would overwhelm analysts. Correlation reduces alert fatigue and enables effective incident response.

**Q: How would you scale this system for production?**  
Replace SQLite with PostgreSQL. Add a message queue (Kafka) for flow ingestion. Deploy ML inference as a separate microservice. Use Redis for the anomaly baseline cache. Add a SIEM integration (Splunk/Elastic) for long-term event storage and search.

---

## Skills Demonstrated

| Skill | Evidence |
|-------|---------|
| Network Security | Flow analysis, IDS concepts, SOC workflow |
| Python Development | FastAPI, Pydantic v2, async/await, SQLite |
| Machine Learning | scikit-learn, feature engineering, model evaluation |
| Frontend Engineering | Next.js 15, TypeScript strict, TanStack Query, Recharts |
| DevOps | Docker multi-stage build, GitHub Actions, health checks |
| Security Practices | Rate limiting, security headers, CORS, input validation |
| Testing | 78 pytest tests, 100% pass rate, scenario coverage |
| Technical Writing | This README, API docs, project report |

---

*Built by Rohit Singh — IIT Delhi Cybersecurity Project*  
*[Live Demo](https://rohitsingh83.github.io/Network-Intrusion-Detection-System-Simulation/) · [GitHub](https://github.com/rohitsingh83/Network-Intrusion-Detection-System-Simulation)*
