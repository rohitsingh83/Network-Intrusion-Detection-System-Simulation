# Interview preparation — exactly 10 questions and answers

## 1. Explain your project.

I built SentinelFlow, a network intrusion detection simulation that uses synthetic network-flow records instead of sending or capturing packets. The Python pipeline validates flow metadata, extracts features such as packet and byte rates, failure ratio, SYN ratio, connection rate, and destination-port diversity, then combines six rule-based detections with a statistical anomaly score. I added optional scikit-learn models, a configurable risk score, alert correlation, a FastAPI API, SQLite persistence, and a SOC-style dashboard where an analyst can review evidence, add notes, and change incident status. I also wrote automated tests and documented the limits of evaluating an IDS on synthetic data.

## 2. What is an IDS, and how does it differ from an IPS?

An IDS monitors authorized telemetry and generates alerts for investigation. An IPS can be positioned to take preventive action, such as blocking or dropping traffic, depending on its design. My project is intentionally an IDS simulation: it detects, scores, correlates, and documents signals, but never blocks systems or generates network traffic.

## 3. How does signature-based detection differ from anomaly-based detection?

A signature checks a predefined condition, such as a high connection rate or repeated failed connections. It is explainable because the rule and measured evidence are visible, but it can miss patterns not covered by a rule. Anomaly detection compares a flow to a baseline and can reveal an unexpected pattern, including one not described by a rule, but can flag legitimate changes. I use a hybrid approach and keep both signals visible to the analyst.

## 4. Which network features did you engineer, and why?

I derived bytes per second, packets per second, failure ratio, SYN ratio, connection rate, and destination diversity, alongside counters such as bytes, packets, duration, failed connections, SYNs, and resets. Rates make volumes comparable across durations. Failure and SYN ratios describe the composition of activity, while destination-port diversity represents a source's windowed fan-out. These features provide context, but a single high value does not prove malicious activity.

## 5. How does your anomaly detector work?

It fits a baseline using records labeled normal in the synthetic training CSV. For each of five behavior features, it stores a mean, standard deviation, and quartiles. New feature values are compared with that reference using standard-deviation and IQR-based scale protection; positive deviations are combined into a 0–100 anomaly score. The baseline is intentionally simple and fixed for repeatability. A real environment would need asset/service-specific baselines, change context, tuning, and drift monitoring.

## 6. How are risk and alert severity calculated?

Rule severities are mapped to a bounded rule-risk value, and corroborating rules add a small uplift. Without ML, the composite uses 60% rule risk and 40% anomaly score. With ML enabled, it uses 40% rules, 30% anomaly, and 30% ML probability converted to a percentage. The result is clamped to 0–100 and mapped to project triage bands and INFO through CRITICAL severity. Those weights and cutoffs are assumptions for a course project, not universal operational thresholds.

## 7. How did you use machine learning, and how did you evaluate it?

ML is an optional enrichment layer. I implemented source code to train Logistic Regression and Random Forest classifiers on synthetic labels and an Isolation Forest on normal records. The trainer uses a stratified held-out split and calculates accuracy, precision, recall, F1, and a confusion matrix. With the current deterministic data, the Random Forest held-out metrics are perfect because the synthetic labels are strongly reflected in generated features. I explicitly treat that as a generator sanity check, not a real-network performance claim.

## 8. What are false positives and false negatives, and why do they matter?

A false positive is legitimate behavior labeled suspicious, such as an authorized backup that crosses a volume threshold. A false negative is suspicious activity classified as normal. False positives contribute to queue fatigue; false negatives can leave important behavior unreviewed. Baseline context, threshold calibration, multiple detectors, asset information, and analyst feedback can improve the balance. Security teams often pay attention to recall while still managing alert volume and precision.

## 9. How does the analyst investigation workflow work in your project?

The flow is validated and stored, detection outputs and evidence are attached, and a rule hit or sufficient risk creates an alert. Similar open alerts from the same source and alert type in a 60-second window are correlated while each flow remains linked. An analyst opens the alert, reviews source/destination, ports, features, rule evidence and anomaly/ML scores, checks relevant authorized context, adds notes, and moves it through investigating, resolved, or false-positive status. The timeline records the disposition.

## 10. How would you improve the project for a real SOC, and what is its biggest limitation?

The largest limitation is that it is a synthetic, local flow simulation, so its baselines and ML results do not represent a live enterprise network. For an approved deployment, I would ingest authorized Zeek, Suricata, NetFlow, or cloud flow telemetry, enrich it with asset/service context, calibrate per-entity baselines, send normalized alerts to a SIEM, add SSO/RBAC, TLS, audit logging, retention, and rate limiting, and monitor model drift. I would validate all changes in an isolated, approved environment and keep human review in the response path.
