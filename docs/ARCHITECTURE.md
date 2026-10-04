# System architecture and project map

## Component architecture

```text
┌─────────────────────────────┐
│ Synthetic dataset generator │  simulator/generate_dataset.py
│ Synthetic flow replay       │  simulator/traffic_simulator.py
└──────────────┬──────────────┘
               │ JSON record to loopback FastAPI only
               ▼
┌─────────────────────────────┐
│ Flow collector / validation │  backend/routes/flows.py + Pydantic
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│ Feature extractor           │  ids/feature_extractor.py
└──────────────┬──────────────┘
               │
     ┌─────────┼───────────────┐
     ▼         ▼               ▼
┌─────────┐ ┌───────────┐ ┌────────────┐
│ Rules   │ │ Anomaly   │ │ Optional ML│
│ engine  │ │ detector  │ │ model       │
└────┬────┘ └─────┬─────┘ └─────┬──────┘
     └────────────┼──────────────┘
                  ▼
        Risk + alert pipeline
                  ▼
        60-second correlation
                  ▼
┌─────────────────────────────┐
│ SQLite security event store │  backend/database.py
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│ SOC analyst console + API   │  frontend/ + backend/app.py
└─────────────────────────────┘
```

## Component responsibilities

1. **Synthetic Traffic Generator:** creates labeled flow records from service-like and abnormal-statistic scenario templates. It writes CSV, not packets.
2. **Traffic Simulator:** produces one JSON record at a time and submits it to the loopback API; only loopback hosts are accepted by the CLI.
3. **Flow Collector:** Pydantic validates required identities and bounded counters, normalizes timestamps, and rejects malformed requests.
4. **Feature Extractor:** converts raw counters to finite numeric features and uses recent source context plus supplied aggregate features for destination diversity.
5. **Rule Engine:** checks six adjustable, explainable conditions and returns measured evidence.
6. **Anomaly Detector:** compares flow metrics to a normal baseline using mean, standard deviation, and IQR-derived scale protection.
7. **Optional ML:** can load a trained supervised classifier or Isolation Forest bundle. The rules/statistics continue to work if the model is absent.
8. **Risk Engine:** normalizes active signal weights, calculates a score and classification, and maps score to severity.
9. **Alert Engine:** creates an alert when a rule hits or configured investigation threshold is crossed.
10. **Correlation:** groups repeated open same-source/same-type alerts in a 60-second window while retaining each contributing flow ID.
11. **Security Database:** stores flow/alert data, rule settings, ML result rows, notes, status events, and occurrence relationships.
12. **SOC Dashboard:** polls the API every five seconds, visualizes traffic/alerts, and provides a safe synthetic replay and analyst workflow.
13. **Tests:** exercise boundary validation, individual rules, risk scoring, storage, REST endpoints, incident status/notes, and safe replay.

## Actual project structure

```text
Network-Intrusion-Detection-System-Simulation/
├── simulator/                 # Synthetic CSV generator and loopback replay client
│   ├── scenarios.py           # Shared scenario catalog / flow-record factory
│   ├── generate_dataset.py    # Reproducible 5,000-row CSV producer
│   └── traffic_simulator.py   # Normal / mixed, slow / fast record feeder
├── ids/                       # Reusable defensive detection modules
│   ├── config.py              # Default signatures, weights and classifications
│   ├── feature_extractor.py   # Validation and feature engineering
│   ├── rule_engine.py         # Explainable threshold rules
│   ├── anomaly_detector.py    # Statistical normal-baseline score
│   ├── risk_engine.py         # Hybrid weights, triage bands, severity
│   ├── alert_engine.py        # Evidence-rich alert objects
│   ├── correlation.py         # 60-second source/type grouping
│   ├── pipeline.py            # Single-flow detection orchestration
│   └── feature_notes.py       # Feature definitions
├── ml/                        # Optional sklearn train, predict, evaluate
├── backend/                   # FastAPI, schemas, persistence, API routes
│   ├── app.py                 # App creation, middleware, static UI host
│   ├── database.py            # SQLite schema, relations and indexes
│   ├── schemas.py             # Pydantic request models
│   ├── services/              # Ingest, query, analytics, incident service layer
│   │   └── ids_service.py
│   ├── routes/                # Flows, alerts, dashboard, rules, simulation
│   ├── models/                # Model-layer notes; SQL table definitions centralized above
│   └── utils/                  # Backend helper extension point
├── frontend/                  # Offline-friendly JS/CSS dashboard; optional Vite
│   └── src/
│       ├── main.js            # Page renderers, charts, filters, investigation modal
│       ├── styles.css         # Responsive visual system
│       ├── services/api.js    # Same-origin API and safe format helpers
│       ├── components/        # Reusable dashboard component notes/functions
│       └── pages/             # Overview, alerts, flows, rules, replay views
├── data/                      # Included synthetic CSV; local SQLite is ignored
├── models/                    # Optional generated ML bundles and evaluation JSON
├── tests/                     # Automated regression tests
├── screenshots/               # Capture destination / evidence checklist
├── docs/                      # API, safety, data, architecture, interview, proof plan
├── reports/                   # Formal project report / evaluation artifacts
├── README.md
├── requirements.txt
├── .env.example
├── .gitignore
└── pyproject.toml
```

The backend uses a small `backend/services/` package with one clearly named orchestration module. The JavaScript console is dependency-light and keeps pages/components as named rendering functions in `frontend/src/main.js`; the optional Vite config does not add a runtime dependency. This avoids shipping a duplicated React app while preserving the full local dashboard/API workflow.

## Data and storage relationships

```text
network_flows (1) ─────────── (many) alert_occurrences (many) ───── alerts (1)
     │                                                                      │
     └── model_results (many)                                 incident_notes (many)
                                                               incident_timeline (many)
rules are independently configured and applied at ingest time.
```

Indexes cover flow timestamps, source/time windows, classifications, alert status/severity, alert source/type/time correlation, and incident-note lookup. SQL uses placeholders for untrusted values. See database source for exact fields and API guide for behavior.

## Real-time choice

The beginner-friendly dashboard uses **polling every five seconds**. It is easy to observe and debug, and is adequate for a local simulation. Server-Sent Events or WebSockets could reduce latency in a larger authorized deployment but would require more lifecycle, authentication, retry, and backpressure handling.
