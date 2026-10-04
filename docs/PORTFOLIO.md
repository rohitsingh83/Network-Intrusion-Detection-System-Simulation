# Resume, LinkedIn, and GitHub proof of work

## A. Resume bullets

- Built **SentinelFlow**, a defensive hybrid IDS simulation in Python/FastAPI that generates and analyzes 5,000 synthetic network-flow records using six explainable signatures, statistical anomaly scoring, and optional scikit-learn detection.
- Engineered flow features (packet/byte rates, failed-connection and SYN ratios, connection rate, and destination diversity), combined detector signals into configurable 0–100 risk bands, and correlated same-source/type alerts across a 60-second window.
- Implemented a SQLite-backed SOC console and REST API with severity/time filters, evidence-rich alert investigation, analyst notes, status timelines, optional API-key protection for writes, and a 42-test automated suite; all attack-like behaviors are represented as data, not packets.

Adjust the bullets to match exactly what you personally ran, tested, and can explain. Do not call the reported synthetic ML score a production benchmark.

## B. Two-line project description

SentinelFlow is a synthetic-only network IDS lab that combines configurable flow signatures, statistical anomaly detection, optional ML, and hybrid risk scoring. It includes a FastAPI/SQLite backend and a responsive SOC dashboard for correlated alerts, evidence-driven investigation, analyst notes, and incident status tracking—without capturing or sending packets.

## C. LinkedIn project description

I built SentinelFlow, a defensive **Network Intrusion Detection System simulation** designed to demonstrate a SOC-style detection-to-investigation workflow without requiring a network lab. A reproducible generator creates synthetic flow records using RFC 5737 documentation IP ranges, and a local replay client sends JSON records only to the loopback API.

The Python/FastAPI pipeline validates flow metadata, engineers connection/packet/byte rates and failure/SYN ratios, checks six explainable signature rules, calculates a statistical anomaly score against normal synthetic traffic, and can optionally add Logistic Regression, Random Forest, or Isolation Forest enrichment. A configurable hybrid risk engine generates evidence-rich alerts and groups repeated source/type alerts across a 60-second window.

The SQLite-backed dashboard provides traffic analytics, alert filters, rule tuning, flow exploration, investigation recommendations, analyst notes, and status/timeline management. I documented the API, safe design, false-positive/false-negative trade-offs, ML confusion matrix, limitations, and a 42-test automated suite. The impressive held-out score in the fixed generated dataset reflects synthetic feature/label separability only; it is not a claim of real-world effectiveness.

**Ethics:** suspicious patterns are represented as synthetic data records only. The project does not scan, probe, exploit, disrupt, or attack public or third-party systems.

## D. Technical skills demonstrated

- Network Security and Network Traffic Analysis
- Intrusion Detection (NIDS / hybrid IDS concepts)
- Python, FastAPI, Pydantic, SQLite, REST APIs
- Synthetic dataset design and reproducible simulation
- Feature engineering and data validation
- Signature / rule-based detection
- Statistical anomaly detection and baseline reasoning
- Optional machine learning: Random Forest, Logistic Regression, Isolation Forest
- Accuracy, precision, recall, F1, confusion-matrix interpretation
- Risk scoring, alert severity, correlation, SOC triage
- Incident investigation, analyst notes, status workflow
- Defensive coding, secure input handling, tests, documentation, Git/GitHub

## E. GitHub repository description

`Defensive network intrusion detection simulation featuring synthetic traffic generation, signature-based and anomaly-based detection, risk scoring, alert correlation, SOC analytics, and optional machine learning.`

Repository name: `Network-Intrusion-Detection-System-Simulation`

## F. Live portfolio demo

The repository includes a GitHub Pages workflow and [publishing guide](GITHUB_PAGES.md). After publishing, add your actual `https://YOUR-USERNAME.github.io/Network-Intrusion-Detection-System-Simulation/` URL here and to your résumé/LinkedIn. Until Pages is enabled in your GitHub account, describe the site as **deployment-ready**, not as publicly hosted. The Pages demo runs client-side and stores state in each visitor's browser; the optional Render Blueprint (`render.yaml`) hosts the separate Python API.
