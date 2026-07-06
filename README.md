# CertFlow AI

CertFlow AI is a backend-first certificate reliability and ownership handoff platform for SRE, platform, and security teams. The Go backend scans TLS endpoints, parses X.509 certificate metadata, persists inventory, computes deterministic risk findings, exposes REST APIs, and generates evidence-backed handoff reports.

The web UI is intentionally simple and sleek: it is a thin client over the Go API so the backend remains the functional core.

## Why This Exists

At large software companies, certificates often live across load balancers, Kubernetes ingress, service mesh, cloud certificate managers, internal APIs, and legacy systems. The outage risk is rarely just "the cert expires." The harder questions are:

- Who owns this certificate?
- Which service depends on it?
- How does it renew?
- Where is the runbook?
- What should the next on-call engineer do?

CertFlow AI turns those questions into scan data, risk findings, APIs, and handoff reports.

## Current MVP

- Go CLI and API server.
- Concurrent TLS endpoint scanning.
- X.509 metadata extraction with `crypto/tls` and `crypto/x509`.
- SQLite-backed persistence for scans, certificates, risks, and reports, with JSON file storage still available for lightweight demos.
- Deterministic risk engine for expiration, missing ownership, and unknown renewal paths.
- Evidence-backed handoff report generation.
- Static landing page and dashboard served by the Go app.

## Run Tests

```bash
go test ./...
```

## Run A Scan

```bash
go run ./cmd/certflow scan \
  --targets fixtures/demo-domains.yaml \
  --db tmp/certflow.db
```

For local TLS demo services with self-signed certificates, add:

```bash
--insecure-skip-verify
```

## Seed Offline Demo Data

If the local environment cannot reach public DNS/TLS endpoints, seed the dashboard with realistic demo inventory:

```bash
go run ./cmd/certflow seed --db tmp/certflow.db
```

SQLite is the default backend for `.db`, `.sqlite`, and `.sqlite3` paths. A `.json` path uses the lightweight JSON store:

```bash
go run ./cmd/certflow seed --db tmp/certflow.json
```

## Start The Web App

```bash
go run ./cmd/certflow serve --db tmp/certflow.db --addr 127.0.0.1:8080
```

Then open:

```text
http://127.0.0.1:8080
```

## API Surface

```text
GET  /v1/healthz
GET  /v1/certificates
GET  /v1/risks
GET  /v1/scans
POST /v1/scans
POST /v1/ai/handoff-reports
```

Example scan request:

```bash
curl -X POST http://127.0.0.1:8080/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "prod-edge",
    "targets": [
      {
        "host": "example.com",
        "port": 443,
        "service_id": "svc-marketing",
        "environment": "prod",
        "owner_team": "web-platform",
        "renewal_method": "acme"
      }
    ]
  }'
```

Example handoff report request:

```bash
curl -X POST http://127.0.0.1:8080/v1/ai/handoff-reports \
  -H 'Content-Type: application/json' \
  -d '{"certificate_id":"cert_example"}'
```

## CLI

```bash
certflow scan   --targets fixtures/demo-domains.yaml --db tmp/certflow.db
certflow seed   --db tmp/certflow.db
certflow serve  --db tmp/certflow.db --addr 127.0.0.1:8080
certflow risks  --db tmp/certflow.db
certflow report --db tmp/certflow.db --certificate-id cert_x --out handoff.md
```

## Architecture

```text
CLI / Web Dashboard
       |
Go HTTP API
       |
Application Service
       |
TLS Scanner ---- Risk Engine ---- Handoff Report Generator
       |
SQLite Store
```

## Roadmap

- Postgres persistence with migrations.
- OpenAPI document generation.
- AWS ACM fixture importer.
- GCP Certificate Manager fixture importer.
- Kubernetes cert-manager importer.
- OpenTelemetry traces and metrics.
- Provider-backed structured AI report generation.
