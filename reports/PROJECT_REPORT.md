# Network Intrusion Detection System (IDS) Simulation — Project Report

## Abstract

SentinelFlow is a defensive network intrusion detection simulation created for cybersecurity education. It accepts synthetic network-flow records, derives behavioral features, evaluates explainable signatures and a statistical normal baseline, optionally enriches results with machine learning, and stores risk-prioritized alerts for a SOC-style analyst workflow. A FastAPI service and SQLite store support a local dashboard, replay lab, alert correlation, incident notes, and status timeline. The complete demonstration can run without a network sensor or external dataset. All suspicious behavior is represented as data; the project does not capture, generate, or transmit attack packets.

## Introduction

Network-facing organizations need to review communication patterns across applications, devices, and cloud services. Security teams combine sensor alerts, flow logs, endpoint events, authentication records, and business context to decide whether an observation merits investigation. An IDS helps surface candidate signals; it does not independently determine intent. SentinelFlow narrows this broad operational workflow into an inspectable student project focused on network-flow metadata and SOC triage.

## Problem Statement

A student may not have access to a production network, authorized packet captures, or a managed SOC. At the same time, an educational IDS project should demonstrate more than a single classifier: it should show data generation, validation, feature extraction, multiple detection approaches, alert storage, analyst workflows, metrics, testing, and ethical controls. The challenge is to provide a usable end-to-end simulation without attacking or collecting data from third-party infrastructure.

## Objectives

1. Generate a reproducible synthetic dataset with at least 5,000 labeled flow records.
2. Model ordinary application/service behavior and several suspicious statistical patterns.
3. Validate record identity, address, protocol, ports, timestamps, and numeric counters.
4. Engineer traffic-rate and behavioral-ratio features.
5. Implement configurable signatures and statistical anomaly detection.
6. Offer supervised and unsupervised ML training/evaluation as an optional component.
7. Combine detector signals into a bounded risk score and severity.
8. Store flows, alert groups, rules, ML results, notes, and status history.
9. Provide a responsive SOC dashboard, filters, investigation detail, and local replay.
10. Demonstrate defensive coding, tests, documentation, and a safe GitHub portfolio.

## Network Security Background

A packet is a unit of network communication; flow records summarize communication over time using endpoint and counter metadata. Network security monitoring looks for deviations from expected service and asset behavior. Typical observations include connection volume, byte/packet rate, service port, protocol, unsuccessful attempts, and destination diversity. These measurements can support investigation but require context: legitimate deployment activity, load tests, backups, inventory tools, and application changes may be unusual without being malicious.

## Intrusion Detection Systems

An IDS monitors authorized data sources and reports possible malicious or policy-violating activity. A network IDS analyzes telemetry from network vantage points. A host IDS focuses on endpoint-local activity. Signature detection matches known conditions; anomaly detection compares measurements with an expected baseline; a hybrid combines signals. An IPS can take preventive action, while this project is intentionally detection-only. The simulated architecture is a network-based hybrid IDS because it analyzes synthetic network flows and fuses rules with statistical scoring and optional ML.

## Existing Approaches

Common defensive platforms use purpose-built sensors and analytics. Signature systems are efficient and explainable for known patterns, but depend on maintained rules. Behavioral systems can reveal previously undocumented deviations but require baselines and can increase false positives. ML can complement both when data quality and evaluation are understood; it cannot substitute for telemetry context, human review, or production security controls. Enterprise SOCs typically centralize these sources in a SIEM/NDR workflow and enrich alerts with assets, identities, reputation, and prior activity.

## Proposed System

SentinelFlow uses a reproducible generator and local JSON flow simulator. The flow intake validates inputs; feature engineering derives rates and ratios; a rule engine checks six static but adjustable conditions; an anomaly detector compares selected features with normal synthetic records; an optional model contributes a probability or outlier score. A weighted risk engine creates an evidence-backed alert. Correlation groups repeated source/type alerts for one minute and preserves each occurrence. SQLite persists data for investigation. The browser dashboard polls the API and supports SOC-style disposition.

## Architecture

```text
Synthetic generator / replay client
              ↓
      FastAPI flow intake
              ↓
     Validation + features
      ┌───────┼─────────┐
      ↓       ↓         ↓
    Rules  Anomaly      Optional ML
      └───────┼─────────┘
              ↓
     Hybrid risk / severity
              ↓
     Alert generation + correlation
              ↓
       SQLite event database
              ↓
       SOC dashboard / analyst
```

The component breakdown, API responsibilities, table relationships, and folder map are documented in `docs/ARCHITECTURE.md`.

## Synthetic Dataset

The included CSV contains 5,000 records, with 75% normal and 25% suspicious examples generated from a deterministic random seed. Its categories include normal web, DNS, SSH, email, and database summaries plus high connection rate, repeated failures, high destination-port diversity, SYN-heavy metadata, unusual transport/service combinations, and high byte volumes. Source and destination addresses use RFC 5737 documentation ranges. `label` is ground truth for offline evaluation only; it is not an input to the live score.

## Traffic Simulation

The local simulator creates a Python dictionary/JSON record for each selected scenario and posts it to the local FastAPI API. It supports normal and mixed modes, slow and fast timing, bounded runs, and Ctrl+C interruption. It validates that the configured API host is loopback. No packet library or remote destination is used. A dashboard replay endpoint offers the same synthetic-only pipeline for quick demonstrations.

## Feature Engineering

The feature extractor validates IP syntax, TCP/UDP/ICMP protocol, port range, and numeric finiteness. Missing optional counters default to zero; negative counters are prevented at the API boundary. It calculates bytes per second, packets per second, average packet size when absent, failed-connection ratio, SYN ratio, connection rate, and destination diversity from either synthetic aggregate features or recent local record context. A zero duration is divided by a 1 ms floor to prevent infinite rates. Features are explanatory measurements, not labels.

## Signature Detection

Six rules evaluate high connection rate, repeated failures, destination-port diversity, SYN-heavy behavior, unexpected transport on a management/database service port, and high byte volume/rate. Thresholds and enabled state are persisted in SQLite and adjustable from the UI. Every rule match contains its ID, severity, configured limit, description, and measured evidence. Conditions are intentionally simple and testable. A match calls for investigation but cannot prove an intrusion.

## Anomaly Detection

The baseline uses only rows labeled normal in the included CSV when present, with a documented fallback when the data file is unavailable. It calculates mean, standard deviation, first quartile, and third quartile for packet rate, byte rate, connection rate, failure ratio, and destination-port diversity. IQR-derived scale protection reduces sensitivity to a zero/very-small standard deviation. Positive deviations are mapped to feature components and combined into a 0–100 score. A time-window moving average would be a possible extension for evolving baselines; the current fixed baseline improves reproducibility and ease of explanation.

## Machine Learning

Optional training supports supervised Random Forest and Logistic Regression and an unsupervised Isolation Forest. Training uses a stratified 75/25 split and computes metrics on the test portion. The actual Random Forest evaluation for the current seed reports 1.00 accuracy, precision, recall, and F1, with confusion matrix `[[938, 0], [0, 312]]` over 1,250 test records. This result is a consequence of deliberately distinct synthetic generation patterns and is not a generalization claim for real traffic. Model artifact can be recreated using `python -m ml.train_model --model random_forest`. Accuracy is interpreted alongside precision, recall, F1, and the confusion matrix.

## Hybrid Detection

The weighted score uses rule risk and statistical anomaly score, plus optional ML probability scaled to 0–100. The defaults are 60/40 without ML and 40/30/30 with ML. Weights normalize to the available signals and risk is bounded. This gives an analyst rule evidence plus anomaly/model context rather than one opaque verdict. Correlated model/rule errors can still occur; the hybrid approach is not automatically more accurate without validation.

## Risk Scoring

Scores map to NORMAL (0–20), LOW RISK (21–40), SUSPICIOUS (41–60), HIGH RISK (61–80), and CRITICAL INVESTIGATION (81–100). Severity maps to INFO, LOW, MEDIUM, HIGH, and CRITICAL. These are local project thresholds that can be adjusted. Real SOC thresholds require calibration with historical authorized telemetry, asset context, impact, false-positive rate, and analyst queue capacity.

## Alert Generation

The engine generates an alert for any rule match or risk score at/above 41. It includes ID, timestamp, source/destination, protocol/ports, primary rule/type, severity, risk, anomaly/ML score, explanation, status, and matched rules. If no rule matched but risk crosses the threshold, the alert type is statistical anomaly. The alert wording emphasizes triage rather than certainty.

## Alert Correlation

Open alerts with matching source IP and alert type within 60 seconds are grouped. A root alert's occurrence count and last-seen timestamp are updated, and `alert_occurrences` links each contributing flow. Raw flow rows are retained. This basic correlation reduces repeated alert noise but does not replace more advanced multi-event correlation, identity/asset context, or incident case management.

## Dashboard

The dashboard shows total/normal/suspicious flows, open and critical alerts, average risk, traffic timeline, severity, protocol, destination ports, risk bands, packet/byte/connection/failure charts, top alert types and source IPs, and recent detections. Alert filters include severity, protocol, type, status, and time window. The flow explorer and rule page support investigation and safe tuning. Clicking an alert displays flow features, rule evidence, anomaly/ML scores, recommended defensive review steps, linked occurrences, notes, and status history.

## SOC Workflow

The modeled process is: event → detection → alert → SOC queue → triage → authorized context review → severity/impact decision → escalation, resolution, or false-positive disposition → documented timeline. Tier 1 analysts commonly validate basic context and record findings; escalation criteria vary by organization. The demo demonstrates evidence review, not an actual incident response claim.

## Testing

The project includes 42 automated tests covering normal TCP/UDP/DNS/HTTPS input, six suspicious patterns, invalid IPs/ports/protocols, missing counters, zero duration, feature/rule/anomaly/risk/alert outputs, correlation, duplicate flow handling, SQLite persistence, dashboard routes, ML probability handling, API validation, status transitions, analyst notes, rule editing, and safe replay. See `docs/TEST_PLAN.md` for ID, scenario, input, expected result, measured result, and pass/fail.

## Security

The code uses synthetic records, reserved documentation addresses, loopback-only replay, schema validation, parameterized SQLite statements, duplicate protection, escaped dashboard output, optional API-key protection for writes, and no payload field. The demo is not a hardened production system: it lacks SSO, roles, TLS termination, centralized immutable audit, and rate limiting. Flow metadata can still expose topology and operations. Approved telemetry requires authorization, least privilege, encryption, access controls, retention limits, secret management, and audit review.

## Results

The implementation generates a reproducible 5,000-row dataset, analyzes records through a common pipeline, produces rule evidence, computes anomaly and risk scores, persists correlated alerts, supports analyst notes/status history, and presents a polling-based SOC dashboard. With a fixed seed, measured normal example flows stay low-risk while synthetic abnormal scenarios trigger expected rule families. Random Forest test metrics are perfect on this generator and explicitly not representative of real-network behavior. Actual automated test output is shown in `docs/TEST_PLAN.md`.

## False Positives

A false positive is expected behavior incorrectly flagged, such as a backup window generating high bytes/s. Excessive false positives can reduce trust and increase queue fatigue. Use service-specific baselines, known change windows, context, risk tuning, and analyst feedback to improve. A threshold increase may reduce noise but can also hide less extreme behavior.

## False Negatives

A false negative is suspicious activity that the system fails to identify. An attacker could remain below simple thresholds, use expected services, or exploit a poor baseline. Multiple detections, contextual enrichment, broader authorized telemetry, measured recall, rule coverage review, and ongoing validation can reduce—but not eliminate—misses.

## Limitations

- Synthetic flow records only; no PCAP, payload, live interface, or real sensor ingestion.
- Simplified single-window feature model and global baseline.
- No asset inventory, user identity, reputation service, threat feed, or enterprise SIEM connector.
- ML metrics measure the synthetic generator, not real environments.
- SQLite and polling are intentionally simple local-demo choices.
- API-key protection is optional and is not a substitute for identity, roles, TLS, or gateway policy.
- Risk bands and rules need operational calibration before any authorized deployment.

## Future Scope

Possible defensive extensions include authorized PCAP import in an isolated lab, Zeek/Suricata/NetFlow parsers, VPC flow log ingestion, per-asset/service baseline profiles, approved threat-intelligence enrichment, SIEM JSON/syslog forwarders, analyst feedback, drift monitoring, richer alert correlation, Postgres, queue-based stream processing, container deployment, SSO/RBAC, centralized audit, and measured rule tuning. Keep collection in approved scope; keep response human-reviewed.

## Conclusion

SentinelFlow demonstrates an end-to-end, safe IDS workflow: synthetic data, network feature extraction, rule and anomaly detections, optional ML, risk prioritization, alert correlation, API persistence, dashboard visualization, and analyst investigation. Its strongest educational value is explainability and repeatability; its strongest caution is that synthetic accuracy and thresholds are not production guarantees. The design is intentionally defensive and can be expanded only with authorized data and security controls.
