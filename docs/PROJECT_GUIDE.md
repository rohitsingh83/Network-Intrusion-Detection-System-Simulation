# SentinelFlow project guide: concepts, detection, and SOC context

## 1. IDS in simple terms

An **Intrusion Detection System (IDS)** watches authorized system or network observations, looks for activity that may be risky, and tells a human what to review. Think of a smoke alarm: it provides a signal and location, but a person still verifies whether there is a fire. A detection does not by itself prove malicious intent.

An organization uses IDS/NDR capabilities to see suspicious behavior earlier, preserve evidence, prioritize investigation, and combine observations from network, endpoint, identity, and firewall sources. This project shows the analytical and analyst-triage workflow using synthetic records, even if the student has no network lab.

## 2. Network and security vocabulary

- **Network traffic:** information exchanged between hosts across a network. It can be observed as packets, sessions, flow summaries, or application/protocol logs.
- **Packet:** a formatted unit of network communication with headers and, in many protocols, payload data. SentinelFlow does not capture or construct packets.
- **Network flow:** a summary of communication, often keyed by source/destination, ports, protocol, and a time window. A flow may include packet/byte counters and duration without retaining payload bytes.
- **Security event:** one recorded observation that may be relevant to security. Example: a flow with a high failed-connection count.
- **Alert:** an event or set of evidence that crosses a detection condition and requires triage. It has severity, reason, and status.
- **Incident:** a managed investigation that brings together related alerts, evidence, analyst notes, timeline, and resolution. An incident can be benign or malicious.
- **Traffic collection:** a sensor or approved log pipeline obtains telemetry. In this lab, the generator produces synthetic dictionaries/CSV rows instead.
- **Feature extraction:** validation and conversion from raw record fields to detector inputs, such as packets per second or a failure ratio.
- **Preprocessing:** missing-value handling, numeric normalization/encoding, and checks. SentinelFlow rejects malformed identities, protocol values, ports, and non-finite counters.

## 3. What the project does

### Simple explanation

The generator creates ordinary-looking synthetic flow records plus unusual statistical examples. The API calculates useful measurements, checks six readable rules, compares behavior to a normal baseline, optionally asks an ML model for a probability, combines those signals into a score, stores any flow and alert, and gives a SOC-style analyst a place to investigate.

### Technical explanation

Pydantic validates the incoming JSON contract. `extract_network_features()` checks IP address syntax, transport protocol and port bounds, normalizes absent optional counters, and derives rates/ratios. `rule_engine.analyze_flow()` produces evidence-bearing matches. `AnomalyDetector` scores positive deviations from normal-only mean/standard deviation and quartile-based scales. When enabled and trained, a scikit-learn bundle adds a supervised probability or unsupervised outlier score. `risk_engine` normalizes available weights and maps the output to risk band/severity. SQLite persists normalized flow rows, alert groups, occurrence links, rules, model results, notes, and status changes. FastAPI exposes the workflow; a polling browser UI renders the response.

### End-to-end workflow

```text
Network Traffic / Synthetic Traffic
                 ↓
Traffic Collection (synthetic generator in this lab)
                 ↓
Feature Extraction and Input Validation
                 ↓
Preprocessing / Derived Rates and Ratios
                 ↓
       ┌─────────────────────────┐
       │ Signature / Rule Engine │
       │ Statistical Anomaly     │
       │ Optional ML Model       │
       └────────────┬────────────┘
                    ↓
            Hybrid Risk Score
                    ↓
             Alert Generation
                    ↓
           SQLite Event Store
                    ↓
             SOC Dashboard
                    ↓
        Analyst Triage / Investigation
```

## 4. IDS types

| Type | Typical input | SentinelFlow relationship |
|---|---|---|
| **NIDS — Network IDS** | Authorized network telemetry, flows, or protocol metadata | Main simulation: flow metadata, no packets |
| **HIDS — Host IDS** | Host logs, process events, file integrity, endpoint activity | Not implemented; endpoint context is an investigation recommendation |
| **Signature-based IDS** | Predefined rules or known pattern matches | Six explicit Python rules with ID, threshold, severity, and evidence |
| **Anomaly-based IDS** | Deviation from learned or configured baseline | Statistical score based on normal synthetic flow features |
| **Hybrid IDS** | Multiple detector types and contextual correlation | Rule + anomaly + optional supervised/unsupervised ML risk fusion |

SentinelFlow is a **network-based hybrid IDS simulation**: the modeled input is network flow metadata, and the decision includes signatures and anomaly scoring, with ML as optional enrichment.

## 5. Industry relevance

IDS and NDR systems are used by:

- **SOC teams:** monitor queues, triage, enrich evidence, escalate and document.
- **Banks and e-commerce:** watch service communication, unexpected access patterns, and high-impact assets.
- **Cloud providers / enterprises / data centers:** review east-west and north-south flow telemetry and service baselines.
- **Government and universities:** centralize authorized network observations across larger environments.
- **MSSPs:** operate alert workflows for multiple approved customer environments.

Relevant roles and the project signal:

| Role | Skills this project can demonstrate |
|---|---|
| SOC Analyst / Tier 1 Analyst | Alert triage, prioritization, status workflow, evidence notes, escalation context |
| Network Security Analyst | Protocol/port understanding, flow analysis, rates, service context |
| Cybersecurity Analyst | Detection tuning, false-positive reasoning, metrics, documentation |
| Security Engineer | Secure API, validation, persistence, controls, architecture |
| Incident Response Analyst | Timeline, related alerts, investigation notes, evidence-driven disposition |
| Threat Detection Engineer | Rule logic, baseline analysis, feature engineering, hybrid detection, test cases |

A student should describe what was actually implemented, show a live safe replay, explain why an alert fired, discuss limitations, and avoid claiming production efficacy.

## 6. Feature engineering reference

| Feature | Calculation / source | Why a defender may review it |
|---|---|---|
| `packet_count` | Packets summarized by record | Volume / burst context |
| `byte_count` | Bytes summarized by record | Bulk-transfer context |
| `duration_seconds` | Flow duration | Needed to normalize rates |
| `bytes_per_second` | bytes ÷ max(duration, 0.001) | Volume rate changes |
| `packets_per_second` | packets ÷ max(duration, 0.001) | Packet burst changes |
| `average_packet_size` | bytes ÷ packets when not supplied | Distinguishes small control exchanges from bulk data patterns |
| `connection_count` | Record or contextual count | Connection density |
| `failed_connection_count` | Synthetic/approved metadata | Repeated failure behavior to investigate with auth/service logs |
| `failure_ratio` | failed ÷ max(connection count, 1) | Proportion of unsuccessful attempts |
| `syn_count` | Metadata counter | TCP connection-attempt context; no actual packets inspected here |
| `rst_count` | Metadata counter | Reset behavior/context |
| `syn_ratio` | SYN count ÷ max(packet count, 1) | High share can justify handshake/flow review |
| `unique_destination_ports` | Supplied window feature or recent flow context | Port diversity can indicate service discovery or inventory tooling |
| `unique_destination_ips` | Supplied window feature or recent flow context | Destination diversity can indicate fan-out |
| `connection_rate` | connections ÷ max(duration, 0.001) | Dense connection activity |

These are indicators, not verdicts. Legitimate testing, backups, service discovery, load balancers, and batch jobs can produce unusual values.

## 7. Signature, anomaly, and hybrid detection

| Method | Strengths | Limits |
|---|---|---|
| Signature-based | Explainable, quick, stable for well-defined patterns, easy to test | Can miss novel patterns; thresholds require context and tuning |
| Anomaly-based | Can surface deviations not represented by an explicit signature | Baseline drift and legitimate changes can cause false positives; quiet/low-and-slow activity may look normal |
| Hybrid | Broadens coverage; preserves rule evidence while adding statistical/ML context | More components to validate; correlated signals can still be wrong |

The anomaly flow is:

```text
Normal baseline → observe flow → compare features → calculate deviation
               → bounded anomaly score (0–100) → analyst context
```

The detector uses means and standard deviations, with quartile/IQR-based scale protection. It retains the top per-feature deviation evidence so an analyst can compare the observed value, baseline mean, and component score. A streaming moving average is a reasonable extension for a time-varying baseline; this implementation keeps a fixed fitted baseline for reproducibility. In a deployed system, baseline segmentation by service, asset, time-of-day, and approved change window is usually more useful than a single global normal profile.

### Project risk model

```text
without ML: 0.60 × rule risk + 0.40 × anomaly score
with ML:    0.40 × rule risk + 0.30 × anomaly score + 0.30 × ML probability × 100
```

Weights are configurable in `ids/config.py`. Final risk is clamped to 0–100. Current bands: `NORMAL` 0–20, `LOW RISK` 21–40, `SUSPICIOUS` 41–60, `HIGH RISK` 61–80, `CRITICAL INVESTIGATION` 81–100. Severity uses INFO, LOW, MEDIUM, HIGH, CRITICAL. A real SOC calibrates thresholds against quality metrics, asset criticality, business impact, and capacity.

## 8. Alert correlation and SOC workflow

```text
Network event → IDS rule/statistical detection → alert → SOC queue
              → triage → investigate authorized context
              → severity/impact assessment → escalate / resolve / false positive
              → record evidence and decision
```

An event is one observation. An alert is a signal requiring attention. An incident is the investigation grouping and disposition. SentinelFlow groups open alerts with the same source IP and alert type within 60 seconds, tracks occurrence count, and preserves contributing flow IDs.

**Tier 1 analyst responsibilities** typically include validating alert context, checking related events and basic allowlisted/expected behavior, documenting findings, assigning/updating queue status, and escalating when evidence or impact warrants. The precise procedures differ by employer. This project supports those concepts but cannot inspect enterprise tools.

For an interview demo: show a normal flow, replay a synthetic multi-port or repeated-failure record, point to the exact matched rule and metrics, open the investigation, explain that score is not proof, add a note, transition status, and mention the test suite and synthetic ML caveat.

## 9. IDS versus IPS

An **IDS detects and alerts**. An **IPS may actively prevent or block** traffic at an enforcement point. SentinelFlow intentionally stops at detection and analyst workflow: automatic blocking of simulated or real systems would be outside scope and could disrupt legitimate traffic.

## 10. False positives and false negatives

- **False positive:** legitimate activity is marked suspicious. Example: an authorized backup creates a high byte-rate record.
- **False negative:** suspicious behavior is treated as normal. Example: behavior remains under simple thresholds or is hidden by an unsuitable baseline.

Both matter: false positives contribute to fatigue; false negatives can leave threats unnoticed. Better asset/service baselines, multiple complementary detections, careful threshold tuning, authorized context, and analyst feedback can improve the balance. They cannot make a detector perfect.

Confusion-matrix terms:

| Actual / Predicted | Normal | Suspicious |
|---|---:|---:|
| Normal | True Negative (TN) | False Positive (FP) |
| Suspicious | False Negative (FN) | True Positive (TP) |

`precision = TP / (TP + FP)` measures how many positive predictions were correct; `recall = TP / (TP + FN)` measures how many suspicious records were found; `F1` is their harmonic mean. Security teams often pay close attention to recall so relevant activity is not missed, while also controlling false-positive volume so analysts can work the queue. The right operating point depends on impact and staffing.

## 11. ATT&CK mapping — evidence first

MITRE ATT&CK is a knowledge base of adversary tactics and techniques. A network alert can be documented against a relevant tactic/technique only when the observable evidence supports that interpretation. For example:

- A broad port-diversity pattern could prompt investigation for **Network Service Discovery (T1046)** under Discovery, but an authorized inventory tool may produce the same statistic.
- Repeated authentication failures may prompt review of **Brute Force (T1110)** under Credential Access only if authentication evidence supports it; this project only has synthetic connection-failure counters.
- Unusual DNS patterns might warrant review against **Application Layer Protocol: DNS (T1071.004)** in Command and Control if supporting evidence exists. A high DNS count alone is not enough to call tunneling or C2.
- High volume alone does not prove **Network Denial of Service (T1498)**; expected backups, data exports, tests, or analytics jobs may explain it.

ATT&CK mapping improves documentation, coverage review, threat hunting, and reporting. SentinelFlow does not automatically assign an ATT&CK technique from an anomaly score.

## 12. SIEM integration concept

```text
IDS → normalized JSON alert → authorized log forwarder/API → SIEM correlation → SOC analyst
```

Safe synthetic sample:

```json
{
  "alert_id": "ALT-1001",
  "source_ip": "192.0.2.15",
  "destination_ip": "198.51.100.20",
  "severity": "HIGH",
  "rule": "High Connection Rate",
  "risk_score": 78
}
```

A production connector would authenticate, normalize timestamps and severity, add source/tool identifiers, protect transport, handle retries/idempotency, and avoid leaking unnecessary sensitive data. This project has no commercial SIEM dependency; its stored JSON fields illustrate the handoff concept.
