# Data dictionary

## Synthetic CSV: `data/network_traffic.csv`

The CSV generator currently creates 5,000 rows by default. The expected field list is declared in `simulator/generate_dataset.py`. Timestamps are synthetic wall-clock times and IPs are RFC 5737 documentation addresses.

| Field | Type | Meaning |
|---|---|---|
| `flow_id` | string | Unique synthetic or replay record identifier |
| `timestamp` | ISO-8601 UTC string | Synthetic observation time |
| `source_ip` | IPv4 string | Source in `192.0.2.0/24` |
| `destination_ip` | IPv4 string | Destination in `198.51.100.0/24` or `203.0.113.0/24` |
| `source_port` | integer 0–65535 | Source-side port metadata |
| `destination_port` | integer 0–65535 | Destination service-port metadata |
| `protocol` | enum string | `TCP`, `UDP`, or `ICMP` |
| `packet_count` | nonnegative number | Packets summarized in this synthetic flow |
| `byte_count` | nonnegative number | Total bytes summarized, no payload retained |
| `duration_seconds` | nonnegative number | Flow duration |
| `connection_count` | nonnegative number | Connections represented by record/window |
| `failed_connection_count` | nonnegative number | Synthetic failed-connection counter |
| `syn_count` | nonnegative number | SYN metadata counter; not a generated packet |
| `rst_count` | nonnegative number | Reset metadata counter |
| `average_packet_size` | nonnegative number | `byte_count / packet_count` when available |
| `unique_destination_ports` | integer | Pre-aggregated window diversity; defaults to one |
| `unique_destination_ips` | integer | Pre-aggregated window destination diversity |
| `label` | enum string | Synthetic ground truth: `NORMAL` or `SUSPICIOUS`; not used for online detection |
| `scenario_type` | string | Generator scenario name |

## Engineered features

`ids/feature_extractor.py` returns validated flow metadata plus `duration`, `bytes_per_second`, `packets_per_second`, `failure_ratio`, `syn_ratio`, and `connection_rate`. It also includes destination diversity. A zero duration uses a safe 0.001 second denominator. Missing numeric counters become zero; malformed IPs/protocols/ports and non-finite numbers are rejected.

## SQLite tables

### `network_flows`

Primary key `flow_id`; indexed by timestamp, source/time, and classification. Stores input counters, engineered `features_json`, matched-rule JSON, risk/anomaly/ML scores, classification, label, scenario, and timestamps. It intentionally has no payload column.

### `alerts`

Primary key `alert_id`; foreign key `flow_id → network_flows.flow_id`. Stores endpoints, protocol/ports, primary rule ID/type, severity, explanation, risk/anomaly/ML scores, status, occurrence count, first/last/update timestamps, resolution fields, and matched-rule JSON. Indexes support status/severity, source/type/time correlation, and creation time.

### `alert_occurrences`

Composite primary key `(alert_id, flow_id)`. Foreign keys link a correlated alert to every flow included in that group. It stores observed time and avoids discarding repeated evidence.

### `rules`

Primary key `rule_id`; stores rule name, description, severity, numeric threshold, enabled switch, JSON sub-configuration, and update time.

### `incident_notes`

Auto-increment `note_id`; foreign key to alert; stores analyst note, author, and creation time. Indexed for alert/timeline reads.

### `incident_timeline`

Auto-increment `timeline_id`; foreign key to alert; stores `from_status`, `to_status`, optional note, actor, and timestamp.

### `model_results` (optional)

Auto-increment `result_id`; foreign key to flow; stores model name, prediction label, score, and timestamp when optional ML is active.

SQLite foreign-key checks are enabled by each connection. Indexes are designed for the classroom query patterns; a production data volume would need retention and storage planning.
