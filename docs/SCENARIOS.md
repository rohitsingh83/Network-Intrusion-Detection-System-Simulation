# Safe virtual simulation and scenario catalog

All examples below are **flow records** representing statistics. They do not create packets or run against a host. Generated source/destination addresses use documentation ranges. Current fixed-seed examples were analyzed with the baseline fit from the included normal synthetic CSV; scores can vary if the dataset seed, rule thresholds, or ML setting changes.

## Scenario definitions and observed fixed-seed examples

| Scenario | Synthetic input summary | Key engineered feature | Rule(s) | Example risk / classification | Alert |
|---|---|---|---|---|---|
| A — Normal HTTPS browsing | TCP/443, ordinary packet/byte counts, a few connections, zero failures | Normal rates, one destination port | None in selected example | 0 / NORMAL | No |
| B — Normal DNS query | UDP/53, small record and zero failures | Low connection density; small bytes | None in selected example | 0 / NORMAL | No |
| C — Repeated failed-connection pattern | Several summarized connections; most marked failed | High failure ratio | IDS-002 | 72 / POTENTIAL INTRUSION | Yes, HIGH in selected example |
| D — High connection rate | Many connections over a short record duration | Connection rate above threshold | IDS-001 | 73 / POTENTIAL INTRUSION | Yes, HIGH in selected example |
| E — Multi-port probing-like pattern | A pre-aggregated source/window diversity count plus synthetic connection metadata | Unique destination ports above threshold | IDS-002 and IDS-003 in selected example | 78 / POTENTIAL INTRUSION | Yes, HIGH in selected example |
| F — SYN-heavy statistical pattern | SYN count is a high share of packet metadata | SYN ratio and SYN count | IDS-004 | 61 / POTENTIAL INTRUSION | Yes, HIGH in selected example |
| G — Abnormally high traffic volume | Multi-megabyte synthetic byte counter over a flow duration | Byte count / bytes per second | IDS-006 | 74 / POTENTIAL INTRUSION | Yes, HIGH in selected example |
| Extra — Unusual service-port activity | UDP metadata on a TCP-oriented management/database port | Destination port + protocol | IDS-005 | 60 / SUSPICIOUS | Yes, MEDIUM in selected example |

Example numbers are actual output of the current implementation with a deterministic RNG seed, not universal guarantees. The risk score is recalculated for each record and is not a probability of compromise. Multi-port values are supplied as synthetic window aggregation; they are not created by contacting destination ports.

## Reproduce exact example calculations

From repository root:

```bash
python - <<'PY'
import csv, random
from ids.anomaly_detector import AnomalyDetector
from ids.feature_extractor import extract_network_features
from ids.pipeline import DetectionPipeline
from simulator.scenarios import ALL_SCENARIOS, make_synthetic_flow

with open('data/network_traffic.csv', newline='', encoding='utf-8') as f:
    rows = list(csv.DictReader(f))
normal = [extract_network_features(row) for row in rows if row['label'] == 'NORMAL']
pipeline = DetectionPipeline(AnomalyDetector().fit(normal))
for scenario in ALL_SCENARIOS:
    flow = make_synthetic_flow(scenario, flow_id='EXAMPLE', rng=random.Random(111))
    result = pipeline.analyze(flow)
    print(scenario, result['risk_score'], result['classification'], result['severity'],
          [r['rule_id'] for r in result['matched_rules']])
PY
```

## Exact virtual walkthrough

1. Install dependencies and generate the dataset:

   ```bash
   python -m venv .venv
   # activate it, then:
   pip install -r requirements.txt
   python -m simulator.generate_dataset --count 5000 --seed 42
   ```

2. Start the backend/dashboard in terminal one:

   ```bash
   uvicorn backend.app:app --host 127.0.0.1 --port 8000
   ```

3. Open `http://127.0.0.1:8000/`. On a new empty DB the app seeds a small set of synthetic demo records so the dashboard is not blank.
4. In terminal two, replay only normal records:

   ```bash
   python -m simulator.traffic_simulator --mode normal --speed fast --count 12
   ```

   Expected: records generally classify `NORMAL`; risk is shown from computed features and baseline.

5. Generate a synthetic abnormal record from the UI (Replay lab → Repeated failures / high connection / multi-port). Alternatively use a local API request:

   ```bash
   curl -X POST http://127.0.0.1:8000/api/simulation/scenario/MULTI_PORT_PROBING_PATTERN?count=1
   ```

   Expected: IDS-003 should match when the generated destination-port diversity meets its configured threshold. Other rules may also match based on the generated counters.

6. Open Alert queue; a matching alert appears. Click it to open its investigation context.
7. Set status `NEW → INVESTIGATING` and save.
8. Add an analyst note such as `Synthetic lab event; reviewed the rule evidence and baseline only.`
9. Resolve with a concise disposition or mark `FALSE_POSITIVE` if the simulated pattern is being used to demonstrate a benign outcome. Status and notes persist to SQLite.
10. Start the continuous client if desired:

    ```bash
    python -m simulator.traffic_simulator --mode mixed --speed fast --count 60
    ```

    Stop with Ctrl+C. The client POSTs flow JSON only to loopback.

## Expected result details

- HTTPS example: TCP/443, typical counters, no failure indicator; no rule expected for a seeded ordinary example.
- DNS example: UDP/53, small byte volume, zero failures; no port-mismatch rule expected.
- Failed-connection example: IDS-002 is expected when count and failure ratio clear the current settings.
- High-rate example: IDS-001 is expected when `connection_count / duration_seconds` clears its configured threshold.
- Multi-port example: IDS-003 is expected when window diversity clears its configured threshold; this is a data field, not real port probing.
- SYN-heavy example: IDS-004 is expected when count and ratio both clear thresholds.
- High-volume example: IDS-006 is expected when byte count or byte rate clears its setting.
- Any result should be triaged with context. A matched rule does not assert attacker identity or intent.
