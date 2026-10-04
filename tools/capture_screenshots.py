"""Capture genuine local SentinelFlow UI and evidence screenshots.

Optional: install requirements-screenshots.txt and `playwright install chromium`.
The script talks only to the local SentinelFlow API and reads the included
synthetic CSV/model evaluation. It does not access or capture any real network.
"""

from __future__ import annotations

import csv
import html
import json
import re
import subprocess
import sys
from pathlib import Path

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "screenshots"
BASE_STYLE = """
*{box-sizing:border-box}body{margin:0;background:#07111f;color:#e7edf7;font-family:Inter,ui-sans-serif,system-ui,Segoe UI,sans-serif;padding:36px}
.wrap{max-width:1200px;margin:auto}.eyebrow{color:#52d5c0;letter-spacing:1.8px;font-size:10px;font-weight:750}.title{font-size:27px;margin:10px 0 6px}.sub{color:#8799ae;font-size:13px;margin-bottom:23px}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.card{border:1px solid rgba(150,174,202,.16);background:linear-gradient(145deg,#102035,#0b1727);border-radius:12px;padding:16px}.card h3{font-size:12px;color:#9eb2c7;margin:0 0 10px;text-transform:uppercase;letter-spacing:.7px}.value{font-size:25px;font-weight:700;color:#eef5fb}.muted{font-size:11px;color:#8497ad;line-height:1.55}.tag{display:inline-block;color:#76dfca;background:rgba(53,215,195,.09);border:1px solid rgba(53,215,195,.14);padding:5px 8px;border-radius:5px;font-size:9px;margin:3px 4px 3px 0}.amber{color:#efc06c}.rose{color:#f18494}.blue{color:#8cb4ff}table{width:100%;border-collapse:collapse;font-size:11px}th,td{text-align:left;padding:9px;border-bottom:1px solid rgba(150,174,202,.12)}th{color:#7489a1;font-size:9px;letter-spacing:.8px}td{color:#bac8d7}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:620px;overflow:auto;background:#06101d;border:1px solid rgba(150,174,202,.12);border-radius:8px;padding:15px;color:#a9e5d8;font-size:10px;line-height:1.55}.footer{margin-top:20px;color:#62768d;font-size:10px}.score{font-size:34px;font-weight:750;color:#f0c269}.bar{height:8px;background:#1b2a3d;border-radius:6px;overflow:hidden;margin-top:8px}.bar i{height:100%;display:block;background:linear-gradient(90deg,#37cdb5,#f0bd5e,#ed7487)}
"""


def report_html(title: str, subtitle: str, content: str) -> str:
    return f"<!doctype html><html><head><meta charset='utf-8'><style>{BASE_STYLE}</style></head><body><main class='wrap'><div class='eyebrow'>SENTINELFLOW · DEFENSIVE CYBERSECURITY LAB</div><h1 class='title'>{html.escape(title)}</h1><div class='sub'>{html.escape(subtitle)}</div>{content}<div class='footer'>Synthetic flow metadata only · No packet capture or transmission</div></main></body></html>"


def save_report(page, filename: str, title: str, subtitle: str, content: str) -> None:
    page.set_content(report_html(title, subtitle, content), wait_until="domcontentloaded")
    page.screenshot(path=str(OUTPUT / filename), full_page=True)


def call_scenario(page, base_url: str, scenario: str) -> dict:
    response = page.request.post(f"{base_url}/api/simulation/scenario/{scenario}?count=1", data={})
    if not response.ok:
        raise RuntimeError(f"Local API returned HTTP {response.status}: {response.text()}")
    payload = response.json()
    return payload["items"][0]


def project_tree() -> str:
    """Build a compact tree from the actual workspace without local artifacts."""
    ignored_dirs = {".git", ".pytest_cache", "__pycache__", "node_modules", ".venv"}
    ignored_files = {"ids.db", "ids.db-shm", "ids.db-wal"}
    lines = [ROOT.name + "/"]
    top_level = sorted(ROOT.iterdir(), key=lambda path: (not path.is_dir(), path.name.lower()))
    top_level = [entry for entry in top_level if entry.name not in ignored_dirs and (not entry.name.startswith(".") or entry.name in {".gitignore", ".github"})]
    for entry_index, entry in enumerate(top_level):
        lines.append(("└── " if entry_index == len(top_level) - 1 else "├── ") + entry.name + ("/" if entry.is_dir() else ""))
        if entry.is_dir():
            children = sorted(entry.iterdir(), key=lambda path: (not path.is_dir(), path.name.lower()))
            children = [child for child in children if child.name not in ignored_dirs | ignored_files and not child.name.endswith((".pyc", ".joblib", ".pkl"))]
            if entry.name == "screenshots":
                children = [child for child in children if child.name == "README.md"]
            for index, child in enumerate(children):
                branch = "└── " if index == len(children) - 1 else "├── "
                label = child.name + ("/" if child.is_dir() else "")
                lines.append("    " + branch + label)
    return "\n".join(lines)


def capture_static_evidence(page) -> None:
    save_report(page, "01-project-structure.png", "Project structure", "Generated from the actual SentinelFlow workspace", f"<div class='card'><pre style='max-height:none;overflow:visible'>{html.escape(project_tree())}</pre></div>")

    # Architecture is the actual project SVG, embedded inline for an offline capture.
    svg = (ROOT / "docs" / "architecture.svg").read_text(encoding="utf-8")
    save_report(page, "02-hybrid-ids-architecture.png", "Hybrid IDS architecture", "Actual architecture.svg rendered locally", f"<div class='card'>{svg}</div>")

    # Sample rows are read directly from the delivered synthetic CSV.
    with (ROOT / "data" / "network_traffic.csv").open(newline="", encoding="utf-8") as handle:
        records = list(csv.DictReader(handle))[:7]
    columns = ["flow_id", "source_ip", "destination_ip", "destination_port", "protocol", "packet_count", "byte_count", "label", "scenario_type"]
    head = "".join(f"<th>{html.escape(col.upper())}</th>" for col in columns)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(row.get(col, ''))}</td>" for col in columns) + "</tr>" for row in records)
    save_report(page, "03-synthetic-dataset.png", "Synthetic flow dataset", "Preview from the included 5,000-row CSV", f"<div class='card'><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table><p class='muted'>Documentation-range addresses only. Labels are evaluation ground truth; the online IDS does not score from labels.</p></div>")

    help_result = subprocess.run([sys.executable, "-m", "simulator.traffic_simulator", "--help"], cwd=ROOT, capture_output=True, text=True, check=True)
    save_report(page, "04-safe-simulator.png", "Local flow simulator", "CLI help from the actual simulator module", f"<pre>{html.escape(help_result.stdout)}</pre>")

    with (ROOT / "models" / "random_forest_evaluation.json").open(encoding="utf-8") as handle:
        metrics = json.load(handle)
    cards = "".join(f"<div class='card'><h3>{html.escape(key)}</h3><div class='value'>{float(metrics[key]):.3f}</div></div>" for key in ["accuracy", "precision", "recall", "f1"])
    save_report(page, "20-ml-evaluation.png", "Held-out ML evaluation", "Measured results from the generated synthetic dataset", f"<div class='grid'>{cards}</div><div class='card' style='margin-top:12px'><p class='muted'>Model: Random Forest · Test rows: {metrics['test_rows']} · Synthetic split only; not production efficacy.</p></div>")

    matrix = metrics["confusion_matrix"]
    matrix_html = f"<div class='card'><table><thead><tr><th>ACTUAL ↓ / PREDICTED →</th><th>NORMAL</th><th>SUSPICIOUS</th></tr></thead><tbody><tr><th>NORMAL</th><td>{matrix[0][0]} · TN</td><td>{matrix[0][1]} · FP</td></tr><tr><th>SUSPICIOUS</th><td>{matrix[1][0]} · FN</td><td>{matrix[1][1]} · TP</td></tr></tbody></table><p class='muted'>Actual values are read from models/random_forest_evaluation.json.</p></div>"
    save_report(page, "21-confusion-matrix.png", "Confusion matrix", "Random Forest · held-out synthetic test split", matrix_html)

    test_result = subprocess.run([sys.executable, "-m", "pytest", "-o", "addopts=", "-q"], cwd=ROOT, capture_output=True, text=True, check=False)
    test_output = (test_result.stdout + "\n" + test_result.stderr).strip()
    if test_result.returncode != 0:
        raise RuntimeError(f"pytest failed during screenshot capture:\n{test_output}")
    match = re.search(r"(\d+ passed(?:, \d+ skipped)?(?:, \d+ warnings?)?)", test_output)
    summary = match.group(1) if match else "pytest completed successfully"
    test_html = f"<div class='grid'><div class='card'><h3>Fresh automated test run</h3><div class='value'>{html.escape(summary)}</div><p class='muted'>Captured by invoking pytest during this screenshot run.</p></div><div class='card'><h3>Coverage areas</h3><p class='muted'>Features · rules · anomaly · risk · alerts · correlation · SQLite · API validation · status lifecycle · safe simulator</p></div><div class='card'><h3>Safety boundary</h3><p class='muted'>Simulator accepts loopback APIs only and posts synthetic flow JSON, never packets.</p></div></div><pre>{html.escape(test_output)}</pre>"
    save_report(page, "22-automated-tests.png", "Automated test summary", "Fresh pytest execution during evidence capture", test_html)


def main() -> None:
    base_url = "http://127.0.0.1:8000"
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1500, "height": 1050}, device_scale_factor=1)
        page = context.new_page()
        page_errors: list[str] = []
        page.on("pageerror", lambda error: page_errors.append(str(error)))
        page.goto(base_url, wait_until="networkidle", timeout=30_000)
        page.locator(".metric-card").first.wait_for(timeout=15_000)

        # Create fresh, actual safe sample events before capturing the dashboard.
        normal = call_scenario(page, base_url, "NORMAL_WEB")
        suspicious = call_scenario(page, base_url, "HIGH_CONNECTION_RATE")
        page.reload(wait_until="networkidle")
        page.locator(".panel-traffic").wait_for(timeout=10_000)
        page.screenshot(path=str(OUTPUT / "12-soc-dashboard.png"), full_page=True)
        for selector, filename in [
            (".panel-traffic", "13-traffic-timeline.png"),
            (".panel-protocol", "14-protocol-distribution.png"),
            (".panel-severity", "15-alert-severity.png"),
            (".panel-types", "16-top-alert-types.png"),
        ]:
            page.locator(selector).screenshot(path=str(OUTPUT / filename))

        page.locator('.nav-item[data-view="alerts"]').click()
        page.locator(".clickable-row").first.wait_for(timeout=10_000)
        page.screenshot(path=str(OUTPUT / "11-alert-generated.png"), full_page=True)
        target_alert_id = (suspicious.get("alert") or {}).get("alert_id")
        target_row = page.locator(f'.clickable-row[data-alert-id="{target_alert_id}"]') if target_alert_id else page.locator(".clickable-row").first
        if target_row.count() == 0:
            target_row = page.locator(".clickable-row").first
        target_row.click()
        page.locator(".investigation-modal").wait_for(timeout=10_000)
        page.screenshot(path=str(OUTPUT / "17-alert-investigation.png"), full_page=True)
        if page.locator("#incident-status").input_value() != "INVESTIGATING":
            page.locator("#incident-status").select_option("INVESTIGATING")
            page.locator('[data-action="update-status"]').click()
        page.locator(".modal-summary .status-investigating").wait_for(state="visible", timeout=10_000)
        page.screenshot(path=str(OUTPUT / "19-incident-status.png"), full_page=True)
        alert_id = page.locator('[data-action="update-status"]').get_attribute("data-alert-id")
        note_text = "Synthetic lab event; reviewed the rule evidence and baseline context."
        detail_response = page.request.get(f"{base_url}/api/alerts/{alert_id}")
        if not detail_response.ok:
            raise RuntimeError(f"Alert detail API returned HTTP {detail_response.status}: {detail_response.text()}")
        existing_notes = detail_response.json().get("notes", [])
        if not any(note.get("note") == note_text for note in existing_notes):
            note_response = page.request.post(
                f"{base_url}/api/alerts/{alert_id}/notes",
                data={"note": note_text, "author": "screenshot-demo"},
            )
            if not note_response.ok:
                raise RuntimeError(f"Note API returned HTTP {note_response.status}: {note_response.text()}")
        page.locator('[data-action="close-modal"]').click()
        page.locator(f'.clickable-row[data-alert-id="{alert_id}"]').click()
        page.get_by_text("Synthetic lab event; reviewed the rule evidence and baseline context.").first.wait_for(timeout=10_000)
        page.screenshot(path=str(OUTPUT / "18-analyst-note.png"), full_page=True)

        page.locator('[data-action="close-modal"]').click()
        page.locator('[data-view="rules"]').click()
        page.locator(".rule-card").first.wait_for(timeout=10_000)
        page.screenshot(path=str(OUTPUT / "08-rule-settings.png"), full_page=True)
        page.locator('[data-view="lab"]').click()
        page.locator(".scenario-card").first.wait_for(timeout=10_000)
        page.screenshot(path=str(OUTPUT / "04-safe-simulator-lab.png"), full_page=True)
        if page_errors:
            raise RuntimeError("SentinelFlow UI raised browser errors:\n" + "\n".join(page_errors))
        page.goto("about:blank")  # end dashboard refresh timers before rendering local evidence cards

        # Evidence cards are rendered from real local API responses and saved metrics.
        n = normal["evaluation"]
        save_report(page, "05-normal-flow-analysis.png", "Normal synthetic web flow", "Live API evaluation", f"<div class='grid'><div class='card'><h3>Source → destination</h3><p class='value'>{html.escape(normal['flow']['source_ip'])} → {html.escape(normal['flow']['destination_ip'])}</p><p class='muted'>{normal['flow']['protocol']} / {normal['flow']['destination_port']} · {normal['flow']['scenario_type']}</p></div><div class='card'><h3>Classification</h3><div class='value'>{html.escape(n['classification'])}</div><p class='muted'>Risk {n['risk_score']}/100 · {html.escape(n['severity'])}</p></div><div class='card'><h3>Detection</h3><p class='muted'>{len(n['matched_rules'])} rule match(es) · anomaly {n['anomaly_score']}/100 · ML {n['ml_probability']}</p></div></div>")
        e = suspicious["evaluation"]
        save_report(page, "06-synthetic-abnormal-flow.png", "High connection-rate synthetic flow", "Live API evaluation; data record only", f"<div class='grid'><div class='card'><h3>Scenario</h3><div class='value'>HIGH CONNECTION RATE</div><p class='muted'>No service was contacted. This row represents summarized counters.</p></div><div class='card'><h3>Detection</h3><div class='value'>{html.escape(e['classification'])}</div><p class='muted'>Matched rules: {html.escape(', '.join(rule['rule_id'] for rule in e['matched_rules']))}</p></div><div class='card'><h3>Risk</h3><div class='score'>{e['risk_score']} / 100</div><div class='bar'><i style='width:{e['risk_score']}%'></i></div></div></div>")
        feature_rows = "".join(f"<tr><td>{html.escape(key)}</td><td>{html.escape(str(value))}</td></tr>" for key, value in e["features"].items() if isinstance(value, (int, float)))
        save_report(page, "07-feature-engineering.png", "Engineered network features", "Actual features returned by the live IDS API", f"<div class='card'><table><thead><tr><th>FEATURE</th><th>VALUE</th></tr></thead><tbody>{feature_rows}</tbody></table></div>")
        rules_html = "".join(f"<div class='card'><h3>{html.escape(rule['rule_id'])} · {html.escape(rule['name'])}</h3><div class='value'>{html.escape(rule['severity'])}</div><p class='muted'>{html.escape(rule['evidence'])}</p></div>" for rule in e["matched_rules"])
        save_report(page, "08-signature-rule-match.png", "Signature evidence", "Rule matches from the high-rate record", f"<div class='grid'>{rules_html or '<div class=card>No rule matched.</div>'}</div>")
        anomaly_rows = "".join(f"<tr><td>{html.escape(item['feature'])}</td><td>{item['value']}</td><td>{item['baseline_mean']}</td><td>{item['component_score']}</td></tr>" for item in e["anomaly_evidence"][:5])
        save_report(page, "09-anomaly-score.png", "Statistical anomaly evidence", f"Score {e['anomaly_score']}/100 with per-feature baseline comparisons", f"<div class='card'><table><thead><tr><th>FEATURE</th><th>OBSERVED</th><th>BASELINE MEAN</th><th>COMPONENT</th></tr></thead><tbody>{anomaly_rows}</tbody></table></div>")
        save_report(page, "10-hybrid-risk-score.png", "Hybrid risk score", "Current local API fusion output", f"<div class='grid'><div class='card'><h3>Composite</h3><div class='score'>{e['risk_score']} / 100</div><div class='bar'><i style='width:{e['risk_score']}%'></i></div></div><div class='card'><h3>Classification</h3><div class='value'>{html.escape(e['classification'])}</div><p class='muted'>{html.escape(e['risk_band'])} · {html.escape(e['severity'])}</p></div><div class='card'><h3>Inputs</h3><p class='muted'>Rule risk {e['rule_score']} · anomaly {e['anomaly_score']} · ML {float(e['ml_probability'] or 0)*100:.1f}%</p></div></div>")
        alert_html = json.dumps(suspicious.get("alert"), indent=2)
        save_report(page, "23-api-response.png", "Flow-ingest API response", "Live response from the synthetic scenario endpoint", f"<pre>{html.escape(alert_html)}</pre>")

        # A compact DB view uses actual local SQLite rows; payloads are not stored.
        import sqlite3
        db_path = ROOT / "data" / "ids.db"
        with sqlite3.connect(db_path) as connection:
            flow_rows = connection.execute("SELECT flow_id, source_ip, destination_ip, protocol, destination_port, risk_score, classification FROM network_flows ORDER BY timestamp DESC LIMIT 6").fetchall()
            alert_rows = connection.execute("SELECT alert_id, alert_type, severity, risk_score, status, occurrence_count FROM alerts ORDER BY last_seen DESC LIMIT 6").fetchall()
        flow_table = "".join("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in row) + "</tr>" for row in flow_rows)
        alert_table = "".join("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in row) + "</tr>" for row in alert_rows)
        db_content = f"<div class='card'><h3>Persisted synthetic flow metadata</h3><table><thead><tr><th>FLOW ID</th><th>SOURCE</th><th>DESTINATION</th><th>PROTOCOL</th><th>PORT</th><th>RISK</th><th>CLASS</th></tr></thead><tbody>{flow_table}</tbody></table></div><div class='card' style='margin-top:12px'><h3>Correlated alert records</h3><table><thead><tr><th>ALERT ID</th><th>TYPE</th><th>SEVERITY</th><th>RISK</th><th>STATUS</th><th>OCCURRENCES</th></tr></thead><tbody>{alert_table}</tbody></table></div>"
        save_report(page, "24-database-records.png", "SQLite flow and alert records", "Actual local database rows · no packet payloads stored", db_content)

        if page_errors:
            raise RuntimeError("SentinelFlow UI raised browser errors:\n" + "\n".join(page_errors))
        page.goto("about:blank")  # end dashboard refresh timers before rendering local evidence cards
        capture_static_evidence(page)
        if page_errors:
            raise RuntimeError("Evidence page raised browser errors:\n" + "\n".join(page_errors))
        print(f"Captured screenshots in {OUTPUT}")
        browser.close()


if __name__ == "__main__":
    main()
