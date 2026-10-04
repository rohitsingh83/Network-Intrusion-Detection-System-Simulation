# Security and privacy notes

## Safe-by-design boundary

- The project uses synthetic records and reserved documentation IP addresses for generated examples.
- The simulator makes HTTP JSON requests only to a loopback IDS API and rejects non-loopback destinations.
- No packet capture, packet crafting, port scanner, exploit logic, credential collection, traffic flood, or automatic block action is included.
- No packet payload column exists in the event schema. Counters and flow metadata can still reveal sensitive network behavior.

## Defensive safeguards in this code

- Pydantic validates request fields and bounds counters, durations, ports, and note lengths.
- IP syntax and protocol values are validated before feature extraction.
- Duplicate flow IDs are rejected with `409`.
- SQLite commands use parameters for values; dynamic query clauses are selected from fixed application-owned fields.
- Notes and alert values are HTML-escaped in the browser before rendering.
- Optional `IDS_API_KEY` is checked with constant-time comparison for API write endpoints (`POST`/`PUT` under `/api`).
- Simulator destination is restricted to loopback; default binding in the Makefile is `127.0.0.1`.
- Secret/configuration values are represented in `.env.example`, not hard-coded into source.

## Important demo limitations

The default local demo has no login, role-based authorization, CSRF/session design, centralized immutable audit pipeline, or production request rate limiting. The optional API key is a starter guard, not an identity system. The included Render Blueprint is an explicitly synthetic public portfolio demo: it generates an API key to protect writes, but dashboard/API reads remain open and the Free plan has ephemeral local storage. Do not enter real or sensitive telemetry. Do not expose an unprotected deployment; this project is not a production SOC service. For hosted-demo limits and the optional persistent disk, see [`DEPLOY_RENDER.md`](DEPLOY_RENDER.md).

## Production controls to add before any authorized real telemetry

1. **Authentication:** organizational SSO/OIDC or a managed API gateway; avoid shared static keys for analyst identity.
2. **Authorization:** least-privilege analyst, rule-editor, and administrator roles; separate read and write scopes.
3. **Encryption:** HTTPS/TLS for browser, APIs, queues, and storage links; managed keys and rotation.
4. **API defense:** reverse-proxy rate limits, request-size constraints, abuse monitoring, CSRF/origin controls where applicable, and safe timeout/retry behavior.
5. **Data governance:** authorized telemetry only, minimized fields, documented purpose, retention/deletion schedule, access reviews, and masking of sensitive identifiers.
6. **Audit:** append-only protected records for rule changes, status transitions, searches, exports, and admin actions; monitor log integrity.
7. **Secrets:** secret manager or environment injection, never commit `.env`, keys, credentials, or customer artifacts.
8. **Secure presentation:** context-aware output encoding, content-security policy, dependency review, and security testing.
9. **Least privilege:** restrict database and process permissions; isolate the service, validate backups, and review access.
10. **Operational safety:** use an approved scope, change window, test plan, and rollback procedure; this project remains IDS-only and does not block traffic.

## Why IDS data is sensitive

Even without payloads, source/destination addresses, service ports, timing, volumes, failure patterns, and analyst notes may reveal network layout, business operations, users, system roles, or incident hypotheses. Treat flow data and alert databases as security-sensitive: limit access, retention, exports, and screenshots; redact identities before public posting; never upload organizational telemetry without authorization.
