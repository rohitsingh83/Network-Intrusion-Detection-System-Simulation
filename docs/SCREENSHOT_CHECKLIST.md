# Screenshot / proof checklist

Current status after the local evidence capture: **items 01–24 are actual PNGs in `screenshots/`**. They were captured from the running local app, real local API responses, included synthetic CSV/model-evaluation JSON, and a fresh pytest run. All traffic representations use synthetic flow JSON and RFC 5737 documentation ranges. No packets were created or sent.

| # | Evidence | Professional filename | Status |
|---:|---|---|---|
| 1 | Actual project folder structure | `01-project-structure.png` | Captured |
| 2 | IDS architecture diagram | `02-hybrid-ids-architecture.png` | Captured |
| 3 | Included synthetic CSV with sample rows | `03-synthetic-dataset.png` | Captured |
| 4 | Simulator CLI help / safe start | `04-safe-simulator.png` | Captured |
| 5 | Normal record + evaluation | `05-normal-flow-analysis.png` | Captured |
| 6 | Suspicious synthetic flow record | `06-synthetic-abnormal-flow.png` | Captured |
| 7 | Feature extraction values | `07-feature-engineering.png` | Captured |
| 8 | Signature evidence from the high-rate scenario | `08-signature-rule-match.png` | Captured |
| 8a | Rule tuning page | `08-rule-settings.png` | Captured |
| 9 | Anomaly score and per-feature baseline comparisons | `09-anomaly-score.png` | Captured |
| 10 | Hybrid risk, classification, severity | `10-hybrid-risk-score.png` | Captured |
| 11 | Generated alert queue | `11-alert-generated.png` | Captured |
| 12 | Full SOC overview | `12-soc-dashboard.png` | Captured |
| 13 | Traffic-over-time panel | `13-traffic-timeline.png` | Captured |
| 14 | Protocol distribution panel | `14-protocol-distribution.png` | Captured |
| 15 | Severity distribution panel | `15-alert-severity.png` | Captured |
| 16 | Top alert types panel | `16-top-alert-types.png` | Captured |
| 17 | Alert investigation and evidence drawer | `17-alert-investigation.png` | Captured |
| 18 | Analyst note on a synthetic alert | `18-analyst-note.png` | Captured |
| 19 | Incident status and audit timeline | `19-incident-status.png` | Captured |
| 20 | Measured held-out ML metrics | `20-ml-evaluation.png` | Captured |
| 21 | Confusion matrix read from evaluation JSON | `21-confusion-matrix.png` | Captured |
| 22 | Fresh automated test output (`pytest -q`) | `22-automated-tests.png` | Captured |
| 23 | Live local synthetic-scenario API response | `23-api-response.png` | Captured |
| 24 | Local SQLite flows + correlated alerts | `24-database-records.png` | Captured |
| 25 | Your Git commit history after you make commits | `25-github-commits.png` | Manual after publishing |
| 26 | Your public repository page with a safe file list | `26-github-repository.png` | Manual after publishing |
| 27 | Your README rendered on GitHub | `27-readme-preview.png` | Manual after publishing |

## Re-capture

See [`../screenshots/README.md`](../screenshots/README.md) for the optional Playwright install and exact capture command:

```bash
python tools/capture_screenshots.py
```

This script writes under `screenshots/`, uses only loopback API calls, adds synthetic example rows plus an idempotent demonstration analyst note to the Git-ignored SQLite database, and runs the test suite before capturing test evidence. For a fresh seeded view, stop the app and remove only the local runtime database `data/ids.db`, then restart with `IDS_SEED_DEMO=true`.

For items 25–27, publish your own repository using the privacy/secret checks in [`GITHUB_STRATEGY.md`](GITHUB_STRATEGY.md). Do not fabricate GitHub screenshots or include keys, personal information, private addresses, or real organization telemetry.
