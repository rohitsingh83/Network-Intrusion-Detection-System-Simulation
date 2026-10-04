# Test plan and execution results

Run from the project root:

```bash
pytest
```

The automated suite has 42 tests in `tests/test_ids.py`. Executed in the project workspace: **42 passed**. One upstream Starlette/httpx deprecation warning was emitted by the test client; it does not affect test outcomes. Rerun locally after changes.

| Test ID | Scenario / Input | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|
| T01 | Normal TCP web flow | TCP flow features parse | Passed | PASS |
| T02 | Normal UDP flow | UDP feature extraction succeeds | Passed | PASS |
| T03 | Normal DNS / UDP 53 | Port 53 retained; zero failure ratio | Passed | PASS |
| T04 | Normal HTTPS / TCP 443 | Port 443 retained | Passed | PASS |
| T05 | High connection-rate record | IDS-001 match | Passed | PASS |
| T06 | Repeated failed connections | IDS-002 match | Passed | PASS |
| T07 | Multi-port aggregate record | Diversity feature and IDS-003 match | Passed | PASS |
| T08 | SYN-heavy record | IDS-004 match | Passed | PASS |
| T09 | High-volume record | IDS-006 match | Passed | PASS |
| T10 | Malformed source IP | Feature extraction raises validation error | Passed | PASS |
| T11 | Malformed destination IP | Feature extraction raises validation error | Passed | PASS |
| T12 | Source port 65536 | Port validation error | Passed | PASS |
| T13 | Destination port -1 | Port validation error | Passed | PASS |
| T14 | Unsupported protocol | Protocol validation error | Passed | PASS |
| T15 | Missing packet count | Safe zero default and finite derived rate | Passed | PASS |
| T16 | Zero duration | 1 ms floor prevents division by zero | Passed | PASS |
| T17 | Known counters | Expected rates and ratios calculated | Passed | PASS |
| T18 | Signature evidence object | Rule ID and evidence returned | Passed | PASS |
| T19 | High-volume anomaly feature row | Score remains between 0 and 100 | Passed | PASS |
| T20 | Out-of-range detector inputs | Hybrid risk remains in 0–100 after clamping | Passed | PASS |
| T21 | High-rate pipeline result | Alert includes ID, source, severity, risk and status | Passed | PASS |
| T22 | Same source/type within 60s | Alerts satisfy correlation condition | Passed | PASS |
| T23 | Different source IP | Alerts do not correlate | Passed | PASS |
| T24 | Case variation in type | Correlation key is normalized | Passed | PASS |
| T25 | SQLite insert and duplicate flow ID | Flow persists; duplicate raises domain error | Passed | PASS |
| T26 | Empty dashboard database | Stats endpoint returns 200 and zero flows | Passed | PASS |
| T27 | Dummy ML model predicts 0.8 | ML probability returned in [0,1] | Passed | PASS |
| T28 | API source IP malformed | POST returns 422 | Passed | PASS |
| T29 | Dataset generator count = 0 | Returns empty list without failure | Passed | PASS |
| T30 | Same flow ID posted twice | First POST 201; second POST 409 | Passed | PASS |
| T31 | API destination port 99999 | POST returns 422 | Passed | PASS |
| T32 | NEW → INVESTIGATING with note | Status and timeline persist | Passed | PASS |
| T33 | Add analyst note | Note persists in returned investigation | Passed | PASS |
| T34 | Update IDS-001 threshold | Updated threshold persists | Passed | PASS |
| T35 | Retrieve stored flow | GET returns engineered features | Passed | PASS |
| T36 | RESOLVED → FALSE_POSITIVE | Invalid transition returns 409 | Passed | PASS |
| T37 | Risk classification boundaries | Low/high example maps to expected bands | Passed | PASS |
| T38 | Synthetic IP generation | RFC 5737 source/destination ranges used | Passed | PASS |
| T39 | Mixed local simulation replay | Six flow records processed; response states no packets | Passed | PASS |
| T40 | Health endpoint | Healthy synthetic-only service response | Passed | PASS |
| T41 | Two same-source high-rate flows within 60 seconds | One grouped alert retains two linked occurrences | Passed | PASS |
| T42 | Simulator configured with a public API hostname | Rejects non-loopback destination and accepts local loopback | Passed | PASS |

## Manual checks

1. Start the backend and load `/`; dashboard and same-origin assets load without CDN calls.
2. Use Replay lab to submit each normal and suspicious record class; verify rule evidence and computed score.
3. Open an alert, move it to `INVESTIGATING`, add a note, resolve it, and inspect the timeline.
4. Toggle a rule and change a threshold; submit a new flow to confirm the updated config is used.
5. Run the standalone simulator; confirm it targets loopback and creates JSON-record events only.
6. Train/evaluate ML; confirm metrics are written from a real held-out split and note synthetic limitations.
7. Inspect SQLite schema and check that no payload column or secret was stored.
