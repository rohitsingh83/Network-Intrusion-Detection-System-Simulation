# Network Intrusion Detection System (IDS) Simulation

**SentinelFlow** is a defensive, synthetic-only hybrid IDS lab with an analyst-first SOC console. It turns safe flow records into explainable rule matches, statistical anomaly scores, an optional scikit-learn prediction, a bounded risk score, correlated alerts, and an investigation timeline.

> **Safety by design:** this application processes flow *data records* only. It does not capture packets, scan hosts, send attack traffic, or contact public systems. The included generator uses RFC 5737 documentation address ranges.
>
> 🌐 **Live Interactive Website:** [https://rohitsingh83.github.io/Network-Intrusion-Detection-System-Simulation/](https://rohitsingh83.github.io/Network-Intrusion-Detection-System-Simulation/)

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white) ![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white) ![Detection](https://img.shields.io/badge/Detection-Hybrid-27b99a) ![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-brightgreen?logo=github) ![Data](https://img.shields.io/badge/Data-Synthetic%20only-556987)

## Overview

The project simulates the flow of network telemetry through a small defensive detection platform. A reproducible CSV generator creates 5,000 labeled flow records; a local simulator can replay JSON records to the API. A feature layer validates metadata and derives rates and ratios. The hybrid IDS combines six explainable signatures, statistical baseline deviations, and an optional supervised/unsupervised model. SQLite stores flows, alerts, rules, model scores, notes, and incident status changes. The dashboard refreshes every five seconds and supports alert triage, threshold tuning, and safe replay.

**Distinctive project angle — evidence-first triage:** each alert retains the contributing flow, matched rule evidence, anomaly/ML scores, correlated occurrence count, investigation notes, recommended review steps, and status timeline. It is a simulation, not a claim that an anomaly proves compromise.

## Problem Statement

SOC teams need to turn high-volume telemetry into a manageable queue of evidence-backed signals. A fixed signature can explain a known pattern but may miss a new behavior; an anomaly detector can surface deviations but often raises false positives. This project demonstrates a small, inspectable, hybrid workflow without requiring real infrastructure or unsafe traffic generation.

## Objectives

- Generate and replay at least 5,000 synthetic records across normal and suspicious behavior classes.
- Validate source/destination IPs, ports, protocols, counters, and timestamps.
- Engineer rates, ratios, and destination-diversity features.
- Apply configurable rule-based and statistical anomaly detection.
- Optionally train Logistic Regression, Random Forest, or Isolation Forest and calculate held-out metrics.
- Combine detector outputs into a 0–100 risk score and triage bands.
- Persist flow evidence and correlated alerts in SQLite.
- Provide a near-real-time SOC dashboard, investigation workflow, REST API, and tests.

## Cybersecurity Relevance

IDS/NDR telemetry is used by SOCs, banks, cloud providers, enterprises, data centers, government organizations, universities, e-commerce companies, and managed security providers. Common use cases include detecting unexpected connection rates, repeated failures, destination-port diversity, protocol/service mismatches, traffic-volume deviations, and behaviors that warrant DNS, firewall, or endpoint-log review. SentinelFlow mirrors the **analysis and triage** part of such workflows; it does not replace Suricata, Zeek, a SIEM, or a production NDR platform.

Relevant role skills include SOC alert triage, network-security analysis, feature engineering, detection-rule design, risk prioritization, incident documentation, REST API development, SQLite data modeling, safe ML evaluation, and defensive secure coding. See [`docs/PROJECT_GUIDE.md`](docs/PROJECT_GUIDE.md) and [`docs/PORTFOLIO.md`](docs/PORTFOLIO.md).

## IDS Concepts

- **IDS:** monitors authorized telemetry and raises alerts for analyst review.
- **NIDS:** analyzes network telemetry such as flows or metadata from a network vantage point.
- **HIDS:** analyzes host-local logs, processes, file changes, or endpoint events.
- **Signature detection:** checks known, explicit conditions; explainable but limited to its rules.
- **Anomaly detection:** compares behavior to a baseline; can surface novel deviations but may increase false positives.
- **Hybrid IDS:** fuses signatures, statistical signals, and optional ML. SentinelFlow primarily simulates a **network-based hybrid IDS** because its input is flow metadata and its detector combines rules with behavior scoring.
- **IDS vs IPS:** an IDS alerts; an IPS may actively prevent traffic. This student project is intentionally detection-only.

A packet is a network-layer unit; a flow is a summary of related communication over time; an event is one observation; an alert is a detection that needs attention; an incident is a collection of related alerts/events that an analyst investigates. No packet payloads are stored here.

## Architecture

```text
Synthetic CSV / Local Flow Simulator
                 │  JSON flow records only
                 ▼
          FastAPI Flow Intake ── validation / duplicate protection
                 ▼
          Feature Extraction ─── rates, ratios, diversity, context
           ┌─────┼─────────┐
           ▼     ▼         ▼
        Rules  Statistical  Optional ML
          └─────┼─────────┘
                 ▼
        Weighted Risk + Triage Band
                 ▼
     Alert Generation + 60s Correlation
                 ▼
   SQLite: flows, alerts, rules, notes, timeline
                 ▼
 SOC Console: overview, filters, investigation, rules, replay
```

![SentinelFlow hybrid IDS architecture](docs/architecture.svg)

Each component is explained in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Technology Stack

- Python 3.10+
- FastAPI + Pydantic for validated APIs
- SQLite for local persistence
- Vanilla JavaScript + inline SVG for the dashboard (no CDN or remote asset dependency)
- Vite is optional for frontend development; the integrated UI works without Node.js
- scikit-learn, NumPy, and joblib for optional ML training/evaluation
- pytest + FastAPI TestClient for automated tests

## Synthetic Dataset

`data/network_traffic.csv` contains **5,000 rows** with 3,750 normal and 1,250 suspicious labels. Records use the documentation IPv4 ranges `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`. Scenarios include `NORMAL_WEB`, `NORMAL_DNS`, `NORMAL_SSH`, `NORMAL_EMAIL`, `NORMAL_DATABASE`, `HIGH_CONNECTION_RATE`, `REPEATED_FAILED_CONNECTIONS`, `MULTI_PORT_PROBING_PATTERN`, `SYN_HEAVY_PATTERN`, `UNUSUAL_PORT_ACTIVITY`, and `HIGH_TRAFFIC_VOLUME`.

Rebuild it deterministically:

```bash
python -m simulator.generate_dataset --count 5000 --seed 42
```

The included data dictionary is [`docs/DATA_DICTIONARY.md`](docs/DATA_DICTIONARY.md). The `label` is ground truth for synthetic evaluation only; the live detection pipeline does not use the label to score a flow.

## Traffic Simulator

`simulator/traffic_simulator.py` creates a new flow record and POSTs JSON only to loopback (`localhost`, `127.0.0.1`, or `::1`). It refuses a non-loopback API URL. Modes:

```bash
python -m simulator.traffic_simulator --mode normal --speed slow --count 20
python -m simulator.traffic_simulator --mode mixed --speed fast --count 60
```

- `--mode normal`: normal synthetic service records.
- `--mode mixed`: normal records plus a suspicious synthetic scenario every sixth record.
- `--speed slow`: 1.5 seconds between records; `--speed fast`: 0.2 seconds.
- Omit `--count` for continuous local replay; press Ctrl+C to stop.

No Scapy, tcpreplay, packet capture, public scanner, or traffic flood is involved.

## Feature Engineering

The feature extractor validates IPs, protocol, port bounds, and finite counters. It derives `bytes_per_second`, `packets_per_second`, `failure_ratio`, `syn_ratio`, `unique_destination_ports`, `unique_destination_ips`, and `connection_rate`. A zero duration uses a 1 ms denominator so output remains finite while a possible burst stays visible. Missing optional numeric counters default to zero; invalid identity/protocol/port inputs fail validation. See [`ids/feature_notes.py`](ids/feature_notes.py) and the feature guide.

## Signature-Based Detection

Six adjustable rules are included: high connection rate, repeated failed connections, destination-port diversity, SYN-heavy flow, unexpected service-port protocol, and high traffic volume. The default thresholds live in `ids/config.py` and are persisted in the `rules` table. Each match includes an ID, severity, threshold, description, and measured evidence. A rule match is an investigation signal, **not proof of an intrusion**.

## Anomaly Detection

The statistical detector builds a baseline from rows labeled `NORMAL` in the generated CSV when available. It evaluates packet rate, byte rate, connection rate, failure ratio, and destination-port diversity using mean/standard deviation plus quartile/IQR scale protection. The result is a 0–100 anomaly score. A real SOC would validate baselines by asset, service, time, and change window; the included baseline is an educational assumption.

## Machine Learning

ML is optional and disabled unless `IDS_ENABLE_ML=true` and a model bundle exists. Train any of the following:

```bash
python -m ml.train_model --model random_forest
python -m ml.train_model --model logistic_regression
python -m ml.train_model --model isolation_forest
```

- **Supervised:** Logistic Regression and Random Forest learn from the synthetic `NORMAL`/`SUSPICIOUS` labels.
- **Unsupervised:** Isolation Forest fits the normal subset and scores outliers.
- The trainer performs a stratified train/test split and calculates accuracy, precision, recall, F1, and a 2×2 confusion matrix. Results are written under `models/`. Isolation Forest scores are mapped to an uncalibrated 0–1 anomaly indicator so the hybrid API can share one interface; do not interpret that value as a calibrated probability.
- Accuracy alone can hide missed suspicious records or excessive false alarms. Review precision, recall, class balance, and the confusion matrix.

With this repository's deterministic generator and Random Forest run, the saved evaluation was calculated from 938 normal and 312 suspicious test records. The observed scores were 1.00 for accuracy, precision, recall, and F1, with confusion matrix `[[938, 0], [0, 312]]`. **This is intentionally easy synthetic data with strong feature/label construction—not evidence of real-world detection efficacy.** Retrain and record new metrics after changing seed, features, or labels.

Enable a trained model by setting `IDS_ENABLE_ML=true` and optionally `IDS_MODEL_PATH=models/random_forest_model.joblib`, then restart the API. Model artifacts are ignored by Git; each user can reproduce one with the command above.

## Hybrid Detection

The pipeline combines:

- Rule risk: strongest rule severity plus a small corroboration uplift.
- Anomaly risk: statistical score from 0 to 100.
- Optional ML: suspicious probability from 0.0 to 1.0, scaled to 0–100.

Defaults: rules 40%, anomaly 30%, ML 30% when ML is active; without ML, rules 60%, anomaly 40%. The weights are configurable in `ids/config.py`. Hybrid detection broadens coverage while preserving rule evidence and analyst context; it does not eliminate false positives or false negatives.

## Risk Scoring

`ids/risk_engine.py` computes a bounded 0–100 composite. Project triage bands are 0–20 normal, 21–40 low risk, 41–60 suspicious, 61–80 high risk, 81–100 critical investigation. Severity maps to INFO, LOW, MEDIUM, HIGH, and CRITICAL. These are **project assumptions**, not universal SOC thresholds. A production team would calibrate them against its traffic, asset context, business impact, analyst capacity, and measured outcomes.

## Alert Generation

An alert is generated when one or more rules match or the composite risk reaches 41. Alert data includes an ID, time, endpoints/ports, protocol, primary rule/type, severity, risk, anomaly/ML score, explanation, and status. States are `NEW`, `INVESTIGATING`, `RESOLVED`, and `FALSE_POSITIVE`. Every description clearly treats a synthetic signal as something requiring triage.

## Alert Correlation

Open alerts with the same source IP and alert type inside a 60-second window are grouped. The root alert tracks `occurrence_count` and `last_seen`; `alert_occurrences` links all contributing flows. This reduces duplicate queue noise without deleting raw flows. Event → observation; alert → detection needing attention; incident → related evidence being investigated.

## SOC Dashboard

Open `http://127.0.0.1:8000/` after starting the backend. The responsive local console includes:

- Total, normal, suspicious, open, critical, and average-risk cards
- Traffic-over-time and packet/byte/connection/failure telemetry charts
- Protocol and destination-port distribution
- Severity, top alert types, source IPs, and risk-score distribution
- Alert table with severity, protocol, type, status, and time-window filters
- Flow explorer, configurable rule page, and safe replay lab
- Alert investigation drawer with rule evidence, per-feature baseline deviations, anomaly/ML scores, recommended review, notes, status changes, correlated occurrences, and timeline
- Automatic refresh every five seconds

The web client uses same-origin API calls and inline SVG; no external fonts/scripts/styles are required. See [`docs/SCREENSHOT_CHECKLIST.md`](docs/SCREENSHOT_CHECKLIST.md) for a proof-of-work capture plan.

## Incident Investigation

Click an alert row to review source/destination context, service ports, features, matched rules, anomaly/ML values, and occurrence history. The UI supports status changes, analyst notes, resolution notes, and a timeline. Recommended review is defensive: compare related authorized logs, confirm asset ownership/service expectations, assess historical baselines, check authentication/firewall evidence, and document disposition. It does not claim or enforce a block.

## API Documentation

Open Swagger at `http://127.0.0.1:8000/api/docs`. Endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/flows` | Validate, analyze, and persist a synthetic flow |
| GET | `/api/flows` | Search/list flows |
| GET | `/api/flows/{id}` | Retrieve flow and engineered features |
| GET | `/api/alerts` | Filter the alert queue |
| GET | `/api/alerts/{id}` | Investigation detail, notes, occurrences, timeline |
| PUT | `/api/alerts/{id}/status` | Advance incident disposition |
| POST | `/api/alerts/{id}/notes` | Add an analyst note |
| GET | `/api/dashboard/stats` | Summary metrics |
| GET | `/api/dashboard/traffic` | Time-series and distribution data |
| GET | `/api/dashboard/alerts` | Alert category analytics |
| GET | `/api/rules` | List active rule configuration |
| PUT | `/api/rules/{id}` | Toggle a rule / tune its threshold |
| POST | `/api/simulation/replay` | Generate 1–200 local synthetic records |
| POST | `/api/simulation/scenario/{type}` | Generate a named safe scenario |

Validation, response bodies, error/status codes, and auth guidance are in [`docs/API.md`](docs/API.md). API write methods support optional `X-API-Key` protection by setting `IDS_API_KEY`. The local demo is unauthenticated by default and should stay bound to localhost. The included Render Blueprint sets a generated `IDS_API_KEY` before binding publicly; its read endpoints remain available and contain synthetic demo data only. Do not expose an unprotected deployment or ingest real/sensitive telemetry. See [`docs/DEPLOY_RENDER.md`](docs/DEPLOY_RENDER.md).

## Installation

Requirements: Python 3.10 or newer. Node/npm are optional.

```bash
cd Network-Intrusion-Detection-System-Simulation
python -m venv .venv
# macOS / Linux
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m simulator.generate_dataset --count 5000 --seed 42
cp .env.example .env
```

`.env.example` is a settings template; this project does not silently load `.env`. On macOS/Linux, load it in the terminal before starting the app with `set -a; source .env; set +a`. On Windows PowerShell, set the needed `$env:IDS_*` variables explicitly. For a clean first run, remove only the local database (`data/ids.db`) if you want the initial demo seed to be recreated. The CSV is safe synthetic data and is included in the repository.

## Usage

**Terminal 1 — start API + dashboard:**

```bash
python run.py
```

**Browser:** `http://127.0.0.1:8000/` (dashboard), `http://127.0.0.1:8000/api/docs` (API docs).

**Terminal 2 — replay 60 mixed synthetic records:**

```bash
python -m simulator.traffic_simulator --mode mixed --speed fast --count 60
```

**Exercise a single scenario from the UI:** choose **Replay lab** and click a scenario card. Each request creates a record, runs it through the same validation/detection pipeline, and refreshes the alert views. For exact end-to-end commands and an expected normal/suspicious walk-through, see [`docs/SCENARIOS.md`](docs/SCENARIOS.md).

Optional Vite developer UI:

```bash
cd frontend
npm install
npm run dev
```

The Vite proxy forwards `/api` and `/health` to local port 8000. This step is not needed to use the integrated dashboard.

## GitHub Pages website

This repository includes a GitHub Actions workflow at [`.github/workflows/deploy-pages.yml`](.github/workflows/deploy-pages.yml) and a complete [GitHub Pages guide](docs/GITHUB_PAGES.md). Once you push to your own GitHub repository and enable **Settings → Pages → Source: GitHub Actions**, it publishes the SOC website at `https://YOUR-USERNAME.github.io/Network-Intrusion-Detection-System-Simulation/`.

The GitHub Pages version works as a static browser demo: dashboard, synthetic replay, rules, alerts, investigations, analyst notes, and status changes run client-side and persist in that browser's localStorage. No backend is required; visitors do not share their demo state. ML is disabled on Pages because GitHub Pages cannot run the Python model. All scenarios remain synthetic data records; no packets or external API calls are made.

### Optional Python API hosting

For the separate FastAPI/SQLite backend, this repository also includes an optional Render Blueprint and [Render guide](docs/DEPLOY_RENDER.md). GitHub Pages alone cannot run a Python API; the guide covers a separate backend and its public-demo limitations. Do not put private server secrets in public browser code.

## Testing

```bash
pytest
```

The automated suite covers **42 tests** across normal and suspicious flows, validation, features, detection, scoring, correlation, SQLite persistence, notes, status transitions, API endpoints, ML probability handling, and safe replay. Current workspace result: **42 passed** (one upstream Starlette/httpx deprecation warning). The test plan is [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md).

## Security

The GitHub Pages demo runs in the browser, stores only synthetic examples in localStorage, and makes no API calls. The optional Python simulator sends JSON only to loopback and never creates packets; the FastAPI backend validates inputs and uses parameterized SQL. Pydantic enforces schema bounds and alert/note text is HTML-escaped. The local backend is unauthenticated by default and binds to localhost. The optional Render template protects write endpoints with a generated key, but read APIs are still public and synthetic-only. Neither mode is a production SOC service: there is no user identity/RBAC, and real telemetry must not be used. See [`docs/SECURITY.md`](docs/SECURITY.md) and [`docs/GITHUB_PAGES.md`](docs/GITHUB_PAGES.md).

## Results

- Reproducible 5,000-row synthetic dataset generated and included.
- Six rule types plus statistical scoring and configurable thresholds.
- Hybrid score and severity generated by the live API.
- Alert correlation joins repeated source/type detections over 60 seconds.
- Analyst workflow persists notes and status history.
- Optional ML evaluation is calculated from an actual split; the perfect score in the current fixed synthetic set is not transferable to real traffic.
- Automated test suite: 42 test cases (see `docs/TEST_PLAN.md`).

## False Positives & False Negatives

A false positive is benign behavior incorrectly flagged (for example, an expected backup burst); a false negative is suspicious behavior classified as normal. The first can create analyst fatigue; the second can leave risk unreviewed. Better baselines, multiple signals, threshold tuning, business/asset context, and feedback can improve the balance. Neither will be eliminated by a classroom simulation.

## Limitations

- Only flow-level synthetic metadata; no packet payload inspection or protocol parser.
- No real-time sensor/PCAP/Zeek/NetFlow ingestion, asset inventory, identity provider, threat-intelligence feed, distributed store, or automated response.
- Statistical baselines and risk thresholds are simple project assumptions.
- Synthetic labels are strongly reflected in generated features; high held-out ML scores indicate separability of this generator, not production effectiveness.
- SQLite and local polling are appropriate for a student demo, not high-volume SOC operations.

## Future Improvements

Defensive extension ideas: authorized PCAP ingestion in an isolated lab; Zeek or Suricata alert/flow imports; approved NetFlow/VPC flow-log ingestion; SIEM JSON/syslog forwarding; contextual asset and threat-intelligence enrichment; per-entity baselines; improved anomaly models and drift monitoring; analyst feedback; RBAC/SSO, TLS, audit review, and rate limiting; Postgres/streaming deployment; containerized lab. Do not replay or collect data outside an approved scope.

## Screenshots

The repository includes **26 real local PNG captures** of the running dashboard, investigations, live API evaluations, SQLite records, actual model metrics, and a fresh `pytest` run. All shown traffic is synthetic flow metadata using reserved documentation ranges; no packets are created or sent.

![SentinelFlow SOC dashboard](screenshots/12-soc-dashboard.png)

![SentinelFlow alert investigation](screenshots/17-alert-investigation.png)

Browse the complete [evidence gallery](screenshots/README.md) and the [capture/status checklist](docs/SCREENSHOT_CHECKLIST.md). To regenerate captures, install the optional Playwright dependency (`pip install -r requirements-screenshots.txt`, then `python -m playwright install chromium`), run the app in one terminal, and execute `python tools/capture_screenshots.py` from another. Linux may need `python -m playwright install-deps chromium` once. The script only calls the local loopback API; it updates the Git-ignored demo database with synthetic example records and runs `pytest -q` for a fresh test screenshot. GitHub commit/repository/README captures are intentionally left for you after publishing your own repository.

## Learning Outcomes

Network-flow concepts, defensive detection engineering, feature construction, rule tuning, baseline statistics, optional ML evaluation, REST API design, SQLite relationships and indexes, SOC alert triage, incident-note handling, safe simulator design, automated testing, portfolio documentation, and clear limitations.

## Ethical Disclaimer

“This project is designed exclusively for defensive cybersecurity education. All suspicious network behavior is represented using synthetic data or authorized isolated lab environments.”

## Repository Details

- **Repository name:** `Network-Intrusion-Detection-System-Simulation`
- **Description:** Defensive network intrusion detection simulation featuring synthetic traffic generation, signature-based and anomaly-based detection, risk scoring, alert correlation, SOC analytics, and optional machine learning.
- **Topics:** `cybersecurity`, `intrusion-detection`, `ids`, `network-security`, `soc`, `python`, `anomaly-detection`, `machine-learning`, `security-analytics`, `threat-detection`, `defensive-security`
- **License:** MIT (see `LICENSE`)

## Author

**Student project by:** Rohit Singh · [GitHub: rohitsingh83](https://github.com/rohitsingh83) · Portfolio-ready descriptions are in [`docs/PORTFOLIO.md`](docs/PORTFOLIO.md).
