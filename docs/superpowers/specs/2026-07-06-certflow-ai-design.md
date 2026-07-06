# CertFlow AI Design Spec

Date: 2026-07-06

## Project Summary

CertFlow AI is a Go-based certificate reliability and ownership handoff platform for SRE, platform, security, and infrastructure teams. It discovers TLS certificates across public endpoints, Kubernetes resources, cloud certificate managers, and internal inventory files; normalizes them into a central certificate graph; detects expiration, ownership, issuer, policy, and deployment risks; and uses AI to generate handoff packets, renewal runbooks, and risk-ranked remediation plans.

The project is inspired by a common enterprise reliability problem, not by any confidential company implementation: at large software companies, certificates often live across many systems, teams, clusters, load balancers, CDNs, ingress controllers, secrets stores, and cloud accounts. Outages happen when the organization knows that a certificate exists but not who owns it, where it is deployed, how it renews, or what breaks if it expires.

CertFlow AI should feel like a small but credible internal platform product that could plausibly be built by an SRE/platform team at a company like Microsoft, Google, Oracle, Salesforce, ServiceNow, Adobe, Intuit, Workday, Atlassian, Snowflake, Palo Alto Networks, CrowdStrike, Akamai, or NetApp.

## Problem Being Solved

Modern software companies operate thousands of services, domains, ingress routes, APIs, internal tools, customer-facing applications, and machine-to-machine integrations. TLS certificates are attached to many of those surfaces. Certificate lifecycle management becomes difficult because the operational truth is distributed:

- Cloud load balancers may use certificates from AWS Certificate Manager, Google Cloud Certificate Manager, Azure Key Vault, or an internal CA.
- Kubernetes ingress and service-mesh certificates may be issued by cert-manager, Vault PKI, SPIFFE/SPIRE, or a custom controller.
- Legacy systems may still rely on manually installed PEM files.
- Domain ownership, service ownership, and certificate ownership may not match.
- Renewal automation may exist, but nobody knows whether it is working until close to expiration.
- Incident responders may not know which team owns a certificate or what deployment path rotates it.
- Handoff between teams often happens through tickets, Slack threads, Confluence pages, or tribal knowledge.

The industry trend makes this more urgent. ACME was standardized to automate certificate issuance, validation, deployment, and revocation because manual CA workflows were slow and error-prone. RFC 8555 describes ACME as a protocol for automating certificate management actions such as issuance and revocation, replacing ad hoc human procedures with machine-implemented protocols. The CA/Browser Forum ballot adopted in 2025 also set a schedule to reduce public TLS certificate lifetimes from 398 days to 200 days in 2026, 100 days in 2027, and 47 days in 2029, which makes manual renewal workflows increasingly unrealistic.

CertFlow AI solves the handoff and reliability layer around certificate automation: not only "can this cert renew?" but "who owns it, where does it run, what depends on it, what is risky about it, and what exactly should the next engineer do?"

## What Top Software Companies Usually Need Around Certs

Large software companies usually separate the certificate problem across several teams:

- SRE teams care about uptime, expiration alerts, blast radius, incident response, and runbooks.
- Platform engineering teams care about internal developer workflows, service onboarding, Kubernetes ingress, service mesh, and infrastructure-as-code.
- Security engineering teams care about PKI policy, key strength, revocation, trust chains, auditability, weak algorithms, and least-privilege issuance.
- Cloud infrastructure teams care about AWS ACM, GCP Certificate Manager, Azure Key Vault, DNS validation, load balancer mappings, and region/account drift.
- Compliance teams care about evidence: who approved a cert, what domains it covers, whether renewals are automated, and whether ownership is documented.

Common failure modes:

- Expired customer-facing certificate causes an outage.
- Internal API certificate expires and breaks service-to-service calls.
- Wildcard certificate is shared across too many services with unclear ownership.
- Certificate is renewed but not deployed to every dependent system.
- Kubernetes secret is rotated but a pod, ingress controller, or sidecar does not reload it.
- Certificate chain changes and breaks older clients.
- Team owns the service but not the DNS zone or certificate issuer.
- A service is transferred to another team without transferring cert renewal knowledge.
- Alerts fire too late or route to the wrong team.
- Inventory exists in a spreadsheet that is stale by the time incident response begins.

CertFlow AI targets these practical gaps.

## Target Users

Primary users:

- SREs responsible for certificate-related availability risk.
- Platform engineers building service ownership and deployment workflows.
- Security engineers responsible for PKI hygiene and certificate policy.

Secondary users:

- Engineering managers receiving ownership transfer reports.
- On-call engineers responding to cert-related incidents.
- New service owners inheriting systems from another team.

## Product Goals

1. Discover TLS certificates from multiple realistic sources.
2. Normalize certificates into an inventory with ownership, service, environment, issuer, and deployment metadata.
3. Detect operational risk before expiration becomes an outage.
4. Generate clean handoff packets for service ownership transfer.
5. Generate renewal runbooks grounded in actual certificate metadata.
6. Expose recruiter-impressive APIs, CLI workflows, database schema, concurrent scanning, and observability.
7. Avoid copying confidential internal systems; use public APIs, mock data, local demos, and generic enterprise patterns.

## Non-Goals

- Do not build a full certificate authority.
- Do not store private keys.
- Do not auto-rotate production certificates in the MVP.
- Do not scan arbitrary third-party networks without explicit user-provided targets.
- Do not make AI the source of truth for security decisions.
- Do not include any proprietary Workiva project details, names, schemas, infrastructure, or implementation assumptions.

## Recommended Tech Stack

Core backend:

- Go 1.22+ for API server, scanner workers, CLI, and integrations.
- Chi for HTTP routing.
- Cobra for CLI commands.
- sqlc for typed database queries.
- goose for migrations.
- SQLite for MVP local development.
- PostgreSQL as a production-mode optional backend.

Certificate and integration layer:

- Go standard library: `crypto/tls`, `crypto/x509`, `net`, `context`, `time`.
- AWS SDK for Go v2 for ACM inventory.
- Google Cloud Go client or REST integration for Certificate Manager inventory.
- Kubernetes `client-go` for cert-manager `Certificate`, `CertificateRequest`, `Issuer`, and `ClusterIssuer` discovery.
- Vault API integration for PKI issuer and certificate metadata.

AI layer:

- OpenAI Responses API or equivalent provider abstraction.
- Structured outputs with JSON Schema for deterministic report generation.
- Prompt inputs limited to normalized certificate metadata, service ownership metadata, alert history, and scan findings.
- Stored AI outputs include model, prompt version, input hash, generated JSON, created timestamp, and reviewer status.

Frontend:

- Next.js, TypeScript, Tailwind, shadcn/ui.
- Dashboard pages for inventory, risk queue, certificate detail, ownership graph, handoff reports, and scan history.

Infrastructure:

- Docker Compose for local API, frontend, and database.
- GitHub Actions for tests, linting, scanner integration tests, and demo cert-expiry checks.
- OpenTelemetry traces and metrics from API, scanner, and AI generation paths.

## Public Industry References

- RFC 8555 defines ACME, a standard protocol for automated certificate issuance, validation, management, and revocation: https://www.rfc-editor.org/rfc/rfc8555
- cert-manager exposes Kubernetes certificate resources such as `Certificate`, `CertificateRequest`, `Issuer`, `ClusterIssuer`, ACME `Order`, and ACME `Challenge`: https://cert-manager.io/docs/reference/api-docs/
- AWS Certificate Manager exposes `ListCertificates` and `DescribeCertificate` APIs for managed certificate inventory: https://docs.aws.amazon.com/acm/latest/APIReference/API_ListCertificates.html and https://docs.aws.amazon.com/acm/latest/APIReference/API_DescribeCertificate.html
- Google Cloud Certificate Manager exposes REST resources for projects, locations, certificates, certificate maps, DNS authorizations, trust configs, and certificate issuance configs: https://cloud.google.com/certificate-manager/docs/reference/certificate-manager/rest
- HashiCorp Vault PKI exposes API operations for certificate issuance, signing, issuers, roles, revocation, CRLs, and tidy operations: https://developer.hashicorp.com/vault/api-docs/secret/pki
- OpenTelemetry provides vendor-neutral APIs and semantic conventions for traces, metrics, and logs: https://opentelemetry.io/docs/specs/otel/
- DigiCert summarizes the CA/Browser Forum 2025 TLS lifetime schedule and why shorter lifetimes make automation essential: https://www.digicert.com/blog/tls-certificate-lifetimes-will-officially-reduce-to-47-days
- OpenAI structured outputs support JSON-Schema-constrained generation, useful for handoff reports and remediation plans that must be machine-readable: https://platform.openai.com/docs/guides/structured-outputs

## System Architecture

CertFlow AI has five major components:

1. Scanner Engine
   - Concurrent Go workers scan TLS endpoints and parse certificate chains.
   - Each scan records leaf certificate details, chain details, SANs, issuer, expiration, signature algorithm, public key algorithm, DNS names, IPs, and connection errors.
   - Scanner supports timeout, retries, per-host concurrency limits, and cancellation through `context.Context`.

2. Inventory Ingestion Layer
   - Imports certificates from endpoint scans, AWS ACM, GCP Certificate Manager, Kubernetes cert-manager resources, Vault PKI metadata, and static ownership files.
   - Normalizes external provider IDs into a common `certificates`, `services`, `owners`, and `deployments` schema.
   - Preserves raw provider payloads for audit/debugging.

3. Risk Engine
   - Computes deterministic risk scores before AI runs.
   - Uses clear rules: expiration window, owner missing, service missing, renewal method unknown, wildcard scope, issuer mismatch, environment criticality, weak signature algorithm, scan failure, and stale handoff documentation.
   - Produces evidence-backed findings.

4. AI Handoff Generator
   - Converts structured findings into handoff summaries, renewal runbooks, owner-specific action plans, and incident-prevention checklists.
   - Uses JSON Schema structured output so reports are reviewable and consistent.
   - Does not invent facts. All generated claims must map back to source evidence IDs.

5. Dashboard and CLI
   - CLI supports local-first workflows for engineers.
   - Dashboard supports inventory review, risk triage, generated handoff docs, and historical scan visibility.

## Data Model

Core tables:

```sql
services (
  id text primary key,
  name text not null,
  environment text not null,
  tier text not null,
  owner_team_id text,
  repo_url text,
  runbook_url text,
  pagerduty_service_id text,
  created_at timestamp not null,
  updated_at timestamp not null
)

owner_teams (
  id text primary key,
  name text not null,
  slack_channel text,
  email text,
  escalation_policy text,
  created_at timestamp not null
)

certificates (
  id text primary key,
  fingerprint_sha256 text unique not null,
  serial_number text not null,
  subject_common_name text,
  issuer_common_name text,
  not_before timestamp not null,
  not_after timestamp not null,
  public_key_algorithm text,
  signature_algorithm text,
  is_ca boolean not null,
  source text not null,
  source_resource_id text,
  raw_pem text,
  raw_provider_json json,
  first_seen_at timestamp not null,
  last_seen_at timestamp not null
)

certificate_sans (
  certificate_id text not null,
  san_type text not null,
  san_value text not null,
  primary key (certificate_id, san_type, san_value)
)

deployments (
  id text primary key,
  certificate_id text not null,
  service_id text,
  environment text not null,
  provider text not null,
  region text,
  endpoint text,
  kubernetes_namespace text,
  kubernetes_secret_name text,
  load_balancer_arn text,
  renewal_method text,
  auto_renewal_enabled boolean,
  last_validated_at timestamp,
  created_at timestamp not null
)

risk_findings (
  id text primary key,
  certificate_id text not null,
  deployment_id text,
  severity text not null,
  category text not null,
  title text not null,
  evidence_json json not null,
  status text not null,
  created_at timestamp not null,
  resolved_at timestamp
)

handoff_reports (
  id text primary key,
  service_id text,
  certificate_id text,
  report_type text not null,
  model text not null,
  prompt_version text not null,
  input_hash text not null,
  structured_output_json json not null,
  reviewer_status text not null,
  created_at timestamp not null
)
```

Important recruiter signal: the schema shows mature thinking around source normalization, auditability, evidence-backed risk findings, ownership metadata, and deterministic/AI separation.

## Core APIs

### Health and Metadata

```http
GET /v1/healthz
GET /v1/version
GET /v1/openapi.json
```

### Scans

```http
POST /v1/scans
Content-Type: application/json

{
  "name": "prod-edge-weekly",
  "targets": [
    {"host": "api.example.com", "port": 443, "service_id": "svc-api", "environment": "prod"},
    {"host": "admin.example.com", "port": 443, "service_id": "svc-admin", "environment": "prod"}
  ],
  "timeout_ms": 3000,
  "max_concurrency": 50,
  "tags": {"source": "domains.yaml", "requested_by": "platform"}
}
```

```http
GET /v1/scans/{scan_id}
GET /v1/scans/{scan_id}/events
GET /v1/scans/{scan_id}/results
POST /v1/scans/{scan_id}/cancel
```

SSE endpoint for live scanner output:

```http
GET /v1/scans/{scan_id}/stream
Accept: text/event-stream
```

Example scan event:

```json
{
  "type": "target_scanned",
  "scan_id": "scan_01h",
  "target": "api.example.com:443",
  "certificate_fingerprint": "sha256:...",
  "expires_in_days": 18,
  "risk_count": 3,
  "duration_ms": 92
}
```

### Certificate Inventory

```http
GET /v1/certificates?expires_before=2026-09-01&environment=prod&severity=high
GET /v1/certificates/{certificate_id}
GET /v1/certificates/{certificate_id}/deployments
GET /v1/certificates/{certificate_id}/risks
GET /v1/certificates/{certificate_id}/history
```

### Services and Ownership

```http
GET /v1/services
POST /v1/services
GET /v1/services/{service_id}
PATCH /v1/services/{service_id}
GET /v1/services/{service_id}/certificates
GET /v1/services/{service_id}/handoff
```

Service creation example:

```json
{
  "id": "svc-doc-publish",
  "name": "Document Publishing API",
  "environment": "prod",
  "tier": "tier_1",
  "owner_team_id": "team-platform-sre",
  "repo_url": "https://github.com/example/doc-publishing",
  "runbook_url": "https://runbooks.example.com/doc-publishing/certs",
  "pagerduty_service_id": "P123ABC"
}
```

### Risk Findings

```http
GET /v1/risks?severity=critical&status=open
GET /v1/risks/{risk_id}
PATCH /v1/risks/{risk_id}
POST /v1/risks/{risk_id}/acknowledge
POST /v1/risks/{risk_id}/resolve
```

Risk finding example:

```json
{
  "id": "risk_01j",
  "severity": "critical",
  "category": "expiration",
  "title": "Production certificate expires in 9 days with no owner team",
  "evidence": {
    "certificate_id": "cert_01f",
    "deployment_id": "dep_01a",
    "not_after": "2026-07-15T12:31:00Z",
    "endpoint": "api.example.com:443",
    "owner_team_id": null,
    "auto_renewal_enabled": false
  }
}
```

### AI Handoff and Runbook Generation

```http
POST /v1/ai/handoff-reports
Content-Type: application/json

{
  "service_id": "svc-doc-publish",
  "certificate_ids": ["cert_01f", "cert_02a"],
  "report_type": "ownership_transfer",
  "audience": "incoming_sre_team",
  "include_runbook": true,
  "include_risk_summary": true
}
```

Response shape:

```json
{
  "report_id": "rep_01k",
  "status": "generated",
  "model": "gpt-5.5",
  "prompt_version": "handoff-v1",
  "output": {
    "executive_summary": "...",
    "current_owner": "team-platform-sre",
    "incoming_owner_checklist": [],
    "renewal_path": [],
    "known_risks": [],
    "rollback_plan": [],
    "evidence_ids": ["risk_01j", "dep_01a", "cert_01f"]
  }
}
```

### Provider Integrations

```http
POST /v1/integrations/aws-acm/sync
POST /v1/integrations/gcp-certificate-manager/sync
POST /v1/integrations/kubernetes-cert-manager/sync
POST /v1/integrations/vault-pki/sync
GET /v1/integrations/{integration_id}/status
```

For the MVP, these can run against mock credentials, local fixture JSON, and local Kubernetes kind clusters. The code should still be structured like production integrations so the design is credible.

## CLI Design

The CLI should be the most polished part of the MVP because infrastructure engineers respect good tooling.

```bash
certflow scan --targets domains.yaml --out scan.json
certflow serve --db certflow.db --port 8080
certflow import aws-acm --fixture fixtures/aws_acm.json
certflow import k8s --context kind-certflow-demo --namespace demo
certflow risks list --severity critical
certflow handoff generate --service svc-doc-publish --format markdown
certflow report export --service svc-doc-publish --out handoff.md
```

Example `domains.yaml`:

```yaml
targets:
  - host: api.example.com
    port: 443
    service_id: svc-api
    environment: prod
    owner_team_id: team-platform
  - host: internal.example.test
    port: 8443
    service_id: svc-internal
    environment: staging
    owner_team_id: team-apps
```

## Risk Scoring

Risk score should be deterministic and explainable before AI is involved.

Inputs:

- Days until expiration.
- Whether certificate is currently reachable.
- Whether certificate appears in multiple deployments.
- Whether owner team is missing.
- Whether runbook URL is missing.
- Whether renewal method is unknown.
- Whether certificate is wildcard.
- Whether certificate is attached to production.
- Whether service tier is critical.
- Whether issuer differs from expected environment policy.
- Whether chain parsing failed.
- Whether SAN list includes unexpected domains.
- Whether key/signature algorithms are weak or deprecated.

Severity example:

- Critical: expires in <= 14 days and environment is production, or already expired and reachable by a known service.
- High: expires in <= 30 days, owner missing, or renewal method unknown.
- Medium: expires in <= 60 days, stale scan, missing runbook, wildcard shared across services.
- Low: documentation or metadata gap without immediate availability risk.

Risk explanation must include evidence fields and never rely solely on AI text.

## AI Design

AI should be used for synthesis, not detection. The deterministic system detects facts and risks; the model turns those facts into human-useful operational artifacts.

AI-generated artifacts:

- Ownership handoff summary.
- Renewal runbook.
- On-call escalation checklist.
- Incident prevention summary.
- Manager-facing risk summary.
- Post-incident draft if a cert was found expired.

Structured output schema example:

```json
{
  "type": "object",
  "required": ["summary", "risks", "handoff_checklist", "renewal_steps", "evidence_ids"],
  "properties": {
    "summary": {"type": "string"},
    "risks": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["severity", "title", "why_it_matters", "evidence_ids"],
        "properties": {
          "severity": {"type": "string"},
          "title": {"type": "string"},
          "why_it_matters": {"type": "string"},
          "evidence_ids": {"type": "array", "items": {"type": "string"}}
        }
      }
    },
    "handoff_checklist": {"type": "array", "items": {"type": "string"}},
    "renewal_steps": {"type": "array", "items": {"type": "string"}},
    "rollback_plan": {"type": "array", "items": {"type": "string"}},
    "evidence_ids": {"type": "array", "items": {"type": "string"}}
  }
}
```

Guardrails:

- The prompt must tell the model to cite only provided evidence IDs.
- The API must reject generated reports that cite nonexistent evidence IDs.
- Reports should be marked `draft` until reviewed.
- Prompt version and input hash must be stored.
- The AI module should be provider-abstracted so OpenAI, Anthropic, or local models can be swapped.

## Dashboard Requirements

Pages:

1. Overview
   - Total certificates.
   - Critical/high risks.
   - Expiring in 14/30/60 days.
   - Ownerless certificates.
   - Scan freshness.

2. Certificate Inventory
   - Search by SAN, issuer, service, team, environment, source.
   - Filter by expiration window and risk severity.
   - Table columns: CN, SAN count, issuer, expires in, owner, source, environment, risk.

3. Certificate Detail
   - Parsed X.509 metadata.
   - SAN list.
   - Chain view.
   - Deployments.
   - Risk findings.
   - Scan history.
   - AI handoff report button.

4. Service Ownership View
   - Services mapped to certificates.
   - Owner team and escalation metadata.
   - Missing runbooks.
   - Handoff readiness score.

5. Handoff Report
   - Generated summary.
   - Renewal path.
   - Checklist.
   - Known risks.
   - Evidence links.
   - Export as Markdown.

6. Scan Runs
   - Live and historical scan results.
   - Errors and duration.
   - Worker concurrency stats.

## Observability

CertFlow AI should instrument itself like a real platform service.

Metrics:

- `certflow_scan_targets_total`
- `certflow_scan_failures_total`
- `certflow_scan_duration_seconds`
- `certflow_certificates_discovered_total`
- `certflow_risk_findings_total`
- `certflow_ai_reports_generated_total`
- `certflow_ai_generation_duration_seconds`
- `certflow_ai_generation_failures_total`

Traces:

- API request trace.
- Scan job trace.
- Per-target TLS dial span.
- Certificate parse span.
- Risk evaluation span.
- AI report generation span.

Logs:

- Structured JSON logs with scan ID, target, service ID, certificate ID, and risk ID.
- No private keys or secrets in logs.

## Security and Privacy

Security requirements:

- Never collect or store private keys.
- Treat raw provider payloads as sensitive.
- Redact tokens, credentials, and secret names where appropriate.
- Require explicit target lists; do not implement broad network discovery in MVP.
- Rate-limit scans.
- Add SSRF protections for API-triggered scans.
- Validate hostnames and ports before scanning.
- Separate read-only provider credentials from any future write/rotation credentials.
- Use least-privilege examples for AWS/GCP/Kubernetes integration docs.

Potential future auth:

- Local mode: no auth, bound to localhost.
- Team mode: OIDC login.
- API mode: signed service tokens.

## Demo Environment

The project should include a local demo that recruiters can run.

Docker Compose services:

- `certflow-api`
- `certflow-web`
- `certflow-db`
- `demo-good-cert-service`
- `demo-expiring-cert-service`
- `demo-ownerless-cert-service`

Demo behavior:

- Generate local test certificates with different expiration windows.
- Start HTTPS services using those certs.
- Run `certflow scan --targets fixtures/demo-domains.yaml`.
- Populate dashboard with normal, warning, and critical certificates.
- Generate a handoff report for the risky service.

This makes the project inspectable without real cloud credentials.

## MVP Milestones

Milestone 1: Go certificate scanner and CLI

- Parse `domains.yaml`.
- Concurrently scan endpoints.
- Extract X.509 metadata.
- Output JSON.
- Unit tests for parser and risk rules.

Milestone 2: API and database

- Add Chi API.
- Add SQLite schema with migrations.
- Store scan runs, certificates, SANs, deployments, and risk findings.
- Add `GET /v1/certificates`, `GET /v1/risks`, and `POST /v1/scans`.

Milestone 3: AI handoff generator

- Add structured AI report generation.
- Store generated reports.
- Validate evidence IDs.
- Export Markdown handoff reports.

Milestone 4: Dashboard

- Build inventory, risk queue, certificate detail, and handoff report pages.
- Add live scan stream.

Milestone 5: Integrations and polish

- Add fixture-based AWS ACM import.
- Add fixture-based GCP Certificate Manager import.
- Add Kubernetes cert-manager import against a local kind cluster.
- Add OpenTelemetry instrumentation.
- Add GitHub Actions CI.

## Recruiter-Facing Highlights

This project should visibly demonstrate:

- Go concurrency for TLS scanning at scale.
- Real X.509 certificate parsing with `crypto/x509`.
- API design using production-style REST resources.
- SQL schema design for normalized infrastructure inventory.
- Deterministic risk scoring separated from AI generation.
- Structured AI outputs with evidence validation.
- Cloud API literacy: AWS ACM, GCP Certificate Manager, Vault PKI, cert-manager.
- SRE thinking: ownership, runbooks, alerting, risk, handoff, observability.
- Security thinking: no private key storage, read-only integrations, auditability, SSRF prevention.
- DevOps maturity: Docker Compose, CI, migrations, tests, OpenTelemetry.

## Resume Bullet Options

Short version:

> Built CertFlow AI, a Go-based certificate reliability platform that concurrently scans TLS endpoints, tracks X.509 expiration and ownership metadata, and uses AI to generate renewal runbooks and service handoff reports.

More technical version:

> Engineered CertFlow AI, a Go/Chi certificate lifecycle platform with concurrent TLS scanning, sqlc-backed certificate inventory, deterministic risk scoring, AWS ACM/Kubernetes cert-manager importers, and JSON-schema AI handoff reports grounded in evidence-linked findings.

SRE-focused version:

> Developed an SRE-focused certificate handoff system that maps certificates to services, owners, deployments, and risk findings, reducing manual cert review workflows through automated expiration detection, runbook generation, and ownership transfer reports.

AI engineering version:

> Built an AI-assisted PKI operations tool that transforms structured certificate inventory and risk evidence into validated handoff packets, renewal playbooks, and incident-prevention summaries using schema-constrained LLM outputs.

## Open Questions

- Should the first public demo use real internet domains like `google.com` and `github.com`, or only local demo services?
- Should the MVP prioritize CLI-first polish or dashboard-first visual impact?
- Should Postgres be included from the beginning or added after SQLite MVP?
- Should the AI reports use OpenAI only, or a provider abstraction from day one?
- Should the first Kubernetes integration target cert-manager CRDs, generic TLS secrets, or both?

## Recommended MVP Decision

Build the project CLI-first with a simple dashboard second:

1. `certflow scan` proves Go, networking, certificates, and concurrency.
2. `certflow serve` proves API and persistence.
3. `certflow handoff generate` proves applied AI.
4. The dashboard makes the result demoable.

This ordering keeps Go central and prevents the project from becoming a frontend-heavy wrapper around an LLM.
