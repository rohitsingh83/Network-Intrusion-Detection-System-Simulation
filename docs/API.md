# REST API reference

Base URL during local development: `http://127.0.0.1:8000`. Interactive OpenAPI UI: `/api/docs`; health probe: `/health`. The browser dashboard and API are served same-origin in the integrated mode.

## Common behavior

- Request and response bodies are JSON. Times are normalized to ISO-8601 UTC.
- Flow schema is validated with Pydantic. IP addresses must parse; protocol is `TCP`, `UDP`, or `ICMP`; ports are integers 0–65535; counters are bounded non-negative finite values; unknown fields are rejected.
- Input labels, when present, are stored only as synthetic dataset ground truth; the IDS scoring path does not use the label.
- SQL uses parameter placeholders. Duplicate `flow_id` values return `409` rather than creating a duplicate.
- Write operations require `X-API-Key` when `IDS_API_KEY` is configured. Local development leaves it blank by default; the Render Blueprint generates one before public binding. Read operations remain unauthenticated and expose only the synthetic demo dataset in this project.
- There is no built-in identity provider, RBAC, request rate limiter, or production audit system. The Render configuration is for a synthetic portfolio demo, not an authorization architecture. Never expose an unprotected instance or put real/sensitive telemetry into it. See [`DEPLOY_RENDER.md`](DEPLOY_RENDER.md).

## Endpoint summary

| Method | Endpoint | Purpose | Authentication / authorization in this build |
|---|---|---|---|
| POST | `/api/flows` | Ingest, analyze, persist a flow | Optional API key; local demo can be open |
| GET | `/api/flows` | Search/list flow records | Local demo read; production should require analyst role |
| GET | `/api/flows/{id}` | Retrieve one flow and features | Local demo read; production should require analyst role |
| GET | `/api/alerts` | Filter alert queue | Local demo read; production should require analyst role |
| GET | `/api/alerts/{id}` | Get investigation details | Local demo read; production should require analyst role |
| PUT | `/api/alerts/{id}/status` | Update incident status | Optional API key; production should require analyst role and audit actor |
| POST | `/api/alerts/{id}/notes` | Add note | Optional API key; production should require analyst role and audit actor |
| GET | `/api/dashboard/stats` | Summary counters | Local demo read |
| GET | `/api/dashboard/traffic` | Traffic/time-series and distributions | Local demo read |
| GET | `/api/dashboard/alerts` | Alert category analytics | Local demo read |
| GET | `/api/rules` | List detection rules | Local demo read; production should require detection-engineer role |
| PUT | `/api/rules/{id}` | Toggle/tune a rule | Optional API key; production should require approved rule-change role |
| POST | `/api/simulation/replay` | Generate local synthetic records | Optional API key; records only |
| POST | `/api/simulation/scenario/{type}` | Generate a named record pattern | Optional API key; records only |

## Flow intake and lookup

### `POST /api/flows`

Request example:

```json
{
  "flow_id": "DEMO-HTTPS-0001",
  "timestamp": "2026-10-03T09:00:00Z",
  "source_ip": "192.0.2.15",
  "destination_ip": "198.51.100.20",
  "source_port": 49152,
  "destination_port": 443,
  "protocol": "TCP",
  "packet_count": 18,
  "byte_count": 12400,
  "duration_seconds": 2.8,
  "connection_count": 3,
  "failed_connection_count": 0,
  "syn_count": 2,
  "rst_count": 0,
  "average_packet_size": 688.9,
  "unique_destination_ports": 1,
  "unique_destination_ips": 1,
  "label": "NORMAL",
  "scenario_type": "NORMAL_WEB"
}
```

Response (`201 Created`) contains `flow`, `evaluation`, and nullable `alert`. `evaluation` includes features, matched rule evidence, rule/anomaly/ML scores, risk, severity, and classification. If the record triggers or joins an alert, `alert` returns that grouped alert. Duplicate flow ID: `409`. Invalid data: `422`. Protected write without key: `401`. Internal storage failure: `500`.

### `GET /api/flows?limit=100&search=192.0.2`

`limit` is 1–500; `search` matches flow ID, source/destination text, or scenario label. Returns `{ "items": [...], "count": ... }`. Success: `200`; invalid query: `422`.

### `GET /api/flows/{id}`

Returns the stored flow, raw counters, engineered `features`, rule matches, score, classification, label (if supplied), and timestamps. `404` when unknown; `200` on success.

## Alert queue and investigation

### `GET /api/alerts`

Supported query parameters: `severity`, `protocol`, `alert_type`, `status`, `hours` (0–8760), `limit` (1–500). Returns `{ "items": [...] }`, newest `last_seen` first. Success: `200`; malformed query values: `422`.

### `GET /api/alerts/{id}`

Returns the root alert plus linked flow/features, matched rules, occurrence list, analyst notes, status timeline, and defensive `recommended_steps`. `404` if not found.

### `PUT /api/alerts/{id}/status`

Request example:

```json
{
  "status": "INVESTIGATING",
  "note": "Compared the flow with the synthetic normal baseline.",
  "resolution_notes": null,
  "actor": "student-analyst"
}
```

Allowed states: `NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`. Expected transitions: `NEW → INVESTIGATING/RESOLVED/FALSE_POSITIVE`; `INVESTIGATING → NEW/RESOLVED/FALSE_POSITIVE`; terminal dispositions can be reopened to `INVESTIGATING`. The response is the refreshed investigation detail. Unknown alert: `404`; invalid transition: `409`; schema error: `422`; key required but absent/wrong: `401`; success: `200`.

### `POST /api/alerts/{id}/notes`

Request: `{ "note": "Reviewed approved test window.", "author": "analyst" }`. Note is trimmed and limited to 2,000 characters; author is limited to 80 characters. It is written to `incident_notes` and also added to the timeline. `201` on success, `404` if the alert does not exist, `422` for invalid input, optional `401` for missing write key.

## Dashboard analytics

### `GET /api/dashboard/stats`

Returns `total_flows`, `normal_flows`, `suspicious_flows`, `total_alerts`, `open_alerts`, `critical_alerts`, `average_risk_score`, and `last_alert_at`. No request body. `200`.

### `GET /api/dashboard/traffic?hours=24&bucket_minutes=10`

`hours` 1–720; `bucket_minutes` 1–1440. Returns normal/suspicious flow timeline, average packets/s, average bytes/s, connection counts, failed attempts, protocol distribution, top destination ports, risk bands, alert severity/type/source breakdowns, and flow-row count. `200`; invalid bounds `422`.

### `GET /api/dashboard/alerts?hours=24`

Returns severity, alert-type, source-IP, and alert-timeline aggregates. `hours` is 1–720. `200`.

## Detection rules

### `GET /api/rules`

Returns each configured rule ID/name/description/severity/threshold/enabled state and rule-specific config. `200`.

### `PUT /api/rules/{id}`

Request body can include either or both: `{ "enabled": false, "threshold": 20 }`. Threshold must be 0–1e15. Unknown rule: `404`; invalid request: `422`; protected write without key: `401`; success: `200` with updated rule.

## Safe simulation endpoints

### `POST /api/simulation/replay`

Request: `{ "mode": "mixed", "count": 12, "seed": 42 }`. `mode` is `normal` or `mixed`; count 1–200. Returns a summary and analyzed record results. No packet is transmitted. `200`; invalid input `422`; write-key failure `401`.

### `POST /api/simulation/scenario/{type}?count=1`

Supported values are the 11 catalog IDs documented in `docs/SCENARIOS.md`. Count is 1–50. Unknown scenario: `404`; invalid count: `422`; successful response `200` with generated results and a no-packets notice.

## Error handling and operational hardening

Common statuses: `200` success; `201` created; `401` configured API key invalid/missing; `404` resource/scenario unknown; `409` duplicate flow or invalid status transition; `422` validation/range error; `500` unexpected server failure. Errors return a JSON `detail` string. Production deployments should return non-sensitive error messages, attach request IDs, centralize audit logs, avoid storing secrets in error text, set request/body limits, and add rate limits at a trusted gateway.
