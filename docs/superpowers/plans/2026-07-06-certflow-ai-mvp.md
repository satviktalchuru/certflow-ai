# CertFlow AI MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a backend-first CertFlow AI MVP with a functional Go scanner, risk engine, JSON persistence, REST API, CLI, and simple web landing/dashboard experience.

**Architecture:** The Go backend is the source of truth. CLI and HTTP handlers call shared application services for scanning, persistence, risk evaluation, and report generation. The frontend is a thin static UI served by the Go server and consumes JSON APIs.

**Tech Stack:** Go standard library, `crypto/tls`, `crypto/x509`, `net/http`, JSON file storage, embedded static HTML/CSS/JS, shell-based local verification.

---

## File Structure

- `go.mod`: Go module definition.
- `cmd/certflow/main.go`: CLI entrypoint for `scan`, `serve`, `risks`, and `report`.
- `internal/certscan/scanner.go`: Concurrent TLS endpoint scanner.
- `internal/certscan/scanner_test.go`: Scanner unit tests with local TLS server.
- `internal/domain/types.go`: Shared domain types for targets, certificates, services, risks, reports, and scans.
- `internal/risk/risk.go`: Deterministic risk engine.
- `internal/risk/risk_test.go`: Risk engine tests.
- `internal/store/json_store.go`: JSON-backed persistence.
- `internal/store/json_store_test.go`: Store tests.
- `internal/app/app.go`: Application service orchestrating scans, risk storage, and reports.
- `internal/app/app_test.go`: App workflow tests.
- `internal/httpapi/server.go`: REST API and static UI server.
- `internal/httpapi/server_test.go`: HTTP handler tests.
- `web/static/index.html`: Landing and app shell.
- `web/static/styles.css`: Sleek operational UI styles.
- `web/static/app.js`: Thin client calling Go APIs.
- `fixtures/demo-domains.yaml`: Demo target list.
- `README.md`: Project overview and run commands.

## Task 1: Domain Model and Risk Engine

**Files:**
- Create: `go.mod`
- Create: `internal/domain/types.go`
- Create: `internal/risk/risk.go`
- Create: `internal/risk/risk_test.go`

- [ ] **Step 1: Write failing risk tests**

Create `internal/risk/risk_test.go` with tests for critical expiration, missing owner, and healthy cert behavior.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/risk`
Expected: FAIL because package implementation does not exist.

- [ ] **Step 3: Implement domain types and risk engine**

Create the shared structs and deterministic risk evaluator.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/risk`
Expected: PASS.

## Task 2: TLS Scanner

**Files:**
- Create: `internal/certscan/scanner.go`
- Create: `internal/certscan/scanner_test.go`

- [ ] **Step 1: Write failing scanner tests**

Use `httptest.NewTLSServer` to prove the scanner extracts a certificate fingerprint, SAN/common name data, expiration, and endpoint metadata.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/certscan`
Expected: FAIL because scanner does not exist.

- [ ] **Step 3: Implement scanner**

Implement concurrent target scanning with `tls.Dialer`, timeout support, SHA-256 fingerprinting, and x509 parsing.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/certscan`
Expected: PASS.

## Task 3: JSON Store and App Workflow

**Files:**
- Create: `internal/store/json_store.go`
- Create: `internal/store/json_store_test.go`
- Create: `internal/app/app.go`
- Create: `internal/app/app_test.go`

- [ ] **Step 1: Write failing store and app tests**

Test that the store persists certificates, risks, scan runs, services, and reports. Test that app scan workflow stores certificates and risks.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store ./internal/app`
Expected: FAIL because store and app do not exist.

- [ ] **Step 3: Implement JSON store and app orchestration**

Implement file-backed persistence and application methods for scan execution, listing certificates, listing risks, and generating evidence-backed handoff reports.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/store ./internal/app`
Expected: PASS.

## Task 4: REST API, CLI, Static UI

**Files:**
- Create: `internal/httpapi/server.go`
- Create: `internal/httpapi/server_test.go`
- Create: `cmd/certflow/main.go`
- Create: `web/static/index.html`
- Create: `web/static/styles.css`
- Create: `web/static/app.js`
- Create: `fixtures/demo-domains.yaml`
- Create: `README.md`

- [ ] **Step 1: Write failing HTTP API tests**

Test `GET /v1/healthz`, `GET /v1/certificates`, `GET /v1/risks`, and `POST /v1/ai/handoff-reports`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/httpapi`
Expected: FAIL because server does not exist.

- [ ] **Step 3: Implement API, CLI, and static UI**

Implement REST handlers, CLI commands, demo fixture parsing, and thin static landing/dashboard assets.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/httpapi`
Expected: PASS.

## Task 5: Verification and Publish Prep

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Run full test suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 2: Run CLI demo scan**

Run: `go run ./cmd/certflow scan --targets fixtures/demo-domains.yaml --db tmp/certflow-demo.json`
Expected: command completes and writes scan results to the JSON database.

- [ ] **Step 3: Run API server smoke test**

Run: `go run ./cmd/certflow serve --db tmp/certflow-demo.json --addr 127.0.0.1:8080`
Expected: server starts and serves `/`, `/v1/healthz`, `/v1/certificates`, and `/v1/risks`.

- [ ] **Step 4: Commit coherent MVP chunk**

Run: `git add . && git commit -m "Build CertFlow AI backend MVP"`
Expected: commit succeeds.

- [ ] **Step 5: Create GitHub repository and push**

Run: `gh repo create certflow-ai --public --source . --remote origin --push`
Expected: repository is created and branch is pushed.
