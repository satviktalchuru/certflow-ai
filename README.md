# CertFlow AI

CertFlow AI is a backend-first certificate reliability platform for SRE, platform, and security teams. It scans TLS endpoints, normalizes certificate inventory, computes ownership and renewal risk, exposes production-style APIs, and generates evidence-backed handoff reports for certificate ownership transfers.

The web app is intentionally lightweight: it gives recruiters and engineers a fast way to traverse the system, while the Go backend remains the core product.

## Demo

Live demo: deploy-ready via Render. See [Deployment](#deployment).

![CertFlow AI dashboard](docs/assets/certflow-dashboard.png)

## Why This Exists

Large software companies often spread certificate ownership across load balancers, Kubernetes ingress, cloud certificate managers, service teams, and internal runbooks. The outage risk is not just that a certificate expires. The harder operational questions are:

- Who owns this certificate?
- Which service depends on it?
- How does it renew?
- Where is the runbook?
- What should the next on-call engineer do?

CertFlow AI turns those questions into scan data, risk findings, API resources, and handoff reports.

## Screenshots

**Certificate Inventory**

![Certificate inventory](docs/assets/certflow-certificates.png)

**Risk Queue**

![Risk queue](docs/assets/certflow-risks.png)

**Generated Handoff Report**

![Generated handoff report](docs/assets/certflow-report.png)

## Backend Highlights

- Go CLI and API server.
- Concurrent TLS scanning with `crypto/tls` and `crypto/x509`.
- SHA-256 certificate fingerprinting and X.509 metadata extraction.
- SQLite, Postgres, and JSON persistence options.
- Deterministic risk engine for expiration, missing ownership, and unknown renewal paths.
- OpenAPI endpoint at `/v1/openapi.json`.
- Fixture importers for AWS ACM, GCP Certificate Manager, and Kubernetes cert-manager.
- Local TLS demo services with generated certificates.
- AI report generator interface with local deterministic output by default and optional OpenAI structured-output generation.
- OpenTelemetry spans and scan metrics with stdout and OTLP exporter support.
- Docker and Render deployment packaging.
- GitHub Actions CI for tests and build verification.

## App Routes

```text
/app
/app/certificates
/app/risks
/app/reports
```

## API Surface

```text
GET  /v1/healthz
GET  /v1/openapi.json
GET  /v1/certificates
GET  /v1/risks
GET  /v1/scans
POST /v1/scans
POST /v1/ai/handoff-reports
```

Example scan request:

```bash
curl -X POST "$CERTFLOW_URL/v1/scans" \
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
curl -X POST "$CERTFLOW_URL/v1/ai/handoff-reports" \
  -H 'Content-Type: application/json' \
  -d '{"certificate_id":"cert_demo_api"}'
```

## Architecture

```text
CLI / Web App
      |
Go HTTP API  ----  OpenAPI
      |
Application Service
      |
TLS Scanner ---- Risk Engine ---- Report Generator
      |
SQLite / Postgres / JSON Store
      |
OpenTelemetry Metrics + Traces
```

## Run Locally

Run tests:

```bash
go test ./...
```

Seed demo data:

```bash
go run ./cmd/certflow seed --db tmp/certflow.db
```

Start the app:

```bash
go run ./cmd/certflow serve --db tmp/certflow.db --addr 127.0.0.1:8080
```

Then open the local app route in your browser:

```text
http://127.0.0.1:8080/app
```

## Local TLS Demo

Start local HTTPS services with generated certificates:

```bash
go run ./cmd/certflow demo-services --targets-out tmp/local-demo-domains.yaml
```

In another terminal, scan them:

```bash
go run ./cmd/certflow scan \
  --targets tmp/local-demo-domains.yaml \
  --db tmp/certflow.db \
  --insecure-skip-verify
```

The local demo includes a healthy certificate, an expiring certificate, and an ownerless certificate.

## Provider Fixture Imports

```bash
go run ./cmd/certflow import \
  --provider aws-acm \
  --fixture fixtures/aws-acm.json \
  --db tmp/certflow.db

go run ./cmd/certflow import \
  --provider gcp-certificate-manager \
  --fixture fixtures/gcp-certificate-manager.json \
  --db tmp/certflow.db

go run ./cmd/certflow import \
  --provider cert-manager \
  --fixture fixtures/cert-manager.json \
  --db tmp/certflow.db
```

## Persistence

SQLite is the default for local development:

```bash
go run ./cmd/certflow seed --db tmp/certflow.db
```

Postgres is supported through `CERTFLOW_DB` or `DATABASE_URL`:

```bash
export CERTFLOW_DB='postgres://user:pass@db.example.com:5432/certflow?sslmode=require'
go run ./cmd/certflow seed
```

JSON storage is available for lightweight demos:

```bash
go run ./cmd/certflow seed --db tmp/certflow.json
```

## AI Report Generation

By default, CertFlow uses a deterministic local report generator so tests and demos do not require network access.

To use OpenAI structured-output generation:

```bash
export CERTFLOW_AI_PROVIDER=openai
export OPENAI_API_KEY=sk-...
export OPENAI_MODEL=gpt-5.5
```

Optional endpoint override:

```bash
export OPENAI_RESPONSES_ENDPOINT=https://api.openai.com/v1/responses
```

## OpenTelemetry

Enable local stdout telemetry:

```bash
export CERTFLOW_OTEL_STDOUT=true
go run ./cmd/certflow serve --db tmp/certflow.db --addr 127.0.0.1:8080
```

Metrics:

- `certflow_scan_targets_total`
- `certflow_scan_failures_total`
- `certflow_scan_duration_seconds`

Export to an OTLP-compatible collector or vendor gateway:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=https://otel-collector.example.com
export OTEL_SERVICE_NAME=certflow-ai
export OTEL_EXPORTER_OTLP_INSECURE=false
```

## Deployment

CertFlow includes:

- `Dockerfile`
- `render.yaml`
- [docs/deployment.md](docs/deployment.md)

The Render blueprint provisions a managed Postgres database and injects its connection string into `CERTFLOW_DB`.

## Resume Bullet

> Built CertFlow AI, a Go-based certificate reliability platform with concurrent TLS/x509 scanning, SQLite/Postgres-backed inventory, OpenAPI REST endpoints, AWS ACM/GCP/cert-manager importers, OpenTelemetry OTLP instrumentation, and AI-assisted handoff reports for SRE ownership workflows.
