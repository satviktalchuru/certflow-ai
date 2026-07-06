package app

import (
	"context"
	"fmt"
	"time"

	"github.com/satviktalchuru/certflow-ai/internal/certscan"
	"github.com/satviktalchuru/certflow-ai/internal/domain"
	"github.com/satviktalchuru/certflow-ai/internal/observability"
	"github.com/satviktalchuru/certflow-ai/internal/report"
	"github.com/satviktalchuru/certflow-ai/internal/risk"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type Store interface {
	SaveScan(domain.ScanRun) error
	SaveReport(domain.HandoffReport) error
	ListCertificates() ([]domain.Certificate, error)
	ListRisks() ([]domain.RiskFinding, error)
	ListReports() ([]domain.HandoffReport, error)
	ListScans() ([]domain.ScanRun, error)
}

type Config struct {
	Store              Store
	Now                func() time.Time
	InsecureSkipVerify bool
	ReportGenerator    report.Generator
	Telemetry          *observability.Telemetry
}

type App struct {
	store              Store
	now                func() time.Time
	insecureSkipVerify bool
	reportGenerator    report.Generator
	telemetry          *observability.Telemetry
}

func New(cfg Config) *App {
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	generator := cfg.ReportGenerator
	if generator == nil {
		generator = report.LocalGenerator{}
	}
	return &App{store: cfg.Store, now: now, insecureSkipVerify: cfg.InsecureSkipVerify, reportGenerator: generator, telemetry: cfg.Telemetry}
}

func (a *App) RunScan(ctx context.Context, name string, targets []domain.Target) (domain.ScanRun, error) {
	if a.store == nil {
		return domain.ScanRun{}, fmt.Errorf("store is required")
	}
	ctx, span := a.startSpan(ctx, observability.SpanName("app", "run_scan"))
	span.SetAttributes(attribute.String("certflow.scan.name", name), attribute.Int("certflow.scan.targets", len(targets)))
	defer span.End()

	started := a.now()
	scanner := certscan.Scanner{Timeout: 5 * time.Second, MaxConcurrency: 20, InsecureSkipVerify: a.insecureSkipVerify}
	if a.telemetry != nil {
		scanner.Tracer = a.telemetry.Tracer
	}
	result := scanner.Scan(ctx, targets)

	findings := make([]domain.RiskFinding, 0)
	for _, cert := range result.Certificates {
		findings = append(findings, risk.Evaluate(started, cert)...)
	}

	scan := domain.ScanRun{
		ID:           "scan_" + compactTimestamp(started),
		Name:         name,
		Targets:      targets,
		StartedAt:    started,
		CompletedAt:  a.now(),
		Certificates: result.Certificates,
		Risks:        findings,
		Errors:       result.Errors,
	}
	if a.telemetry != nil {
		_ = a.telemetry.RecordScanResult(ctx, "endpoint", len(targets), len(result.Errors), scan.CompletedAt.Sub(started).Seconds())
	}
	if err := a.store.SaveScan(scan); err != nil {
		span.RecordError(err)
		return domain.ScanRun{}, err
	}
	return scan, nil
}

func (a *App) ListCertificates() ([]domain.Certificate, error) {
	return a.store.ListCertificates()
}

func (a *App) ListRisks() ([]domain.RiskFinding, error) {
	return a.store.ListRisks()
}

func (a *App) ListReports() ([]domain.HandoffReport, error) {
	return a.store.ListReports()
}

func (a *App) ListScans() ([]domain.ScanRun, error) {
	return a.store.ListScans()
}

func (a *App) GenerateHandoffReport(certificateID string) (domain.HandoffReport, error) {
	ctx, span := a.startSpan(context.Background(), observability.SpanName("app", "generate_handoff_report"))
	span.SetAttributes(attribute.String("certflow.certificate_id", certificateID))
	defer span.End()

	certs, err := a.store.ListCertificates()
	if err != nil {
		span.RecordError(err)
		return domain.HandoffReport{}, err
	}
	var cert domain.Certificate
	found := false
	for _, candidate := range certs {
		if candidate.ID == certificateID {
			cert = candidate
			found = true
			break
		}
	}
	if !found {
		err := fmt.Errorf("certificate %q not found", certificateID)
		span.RecordError(err)
		return domain.HandoffReport{}, err
	}

	allRisks, err := a.store.ListRisks()
	if err != nil {
		span.RecordError(err)
		return domain.HandoffReport{}, err
	}
	riskTitles := make([]string, 0)
	evidenceIDs := make([]string, 0)
	matchingRisks := make([]domain.RiskFinding, 0)
	for _, finding := range allRisks {
		if finding.CertificateID == certificateID {
			matchingRisks = append(matchingRisks, finding)
			riskTitles = append(riskTitles, fmt.Sprintf("%s: %s", finding.Severity, finding.Title))
			evidenceIDs = append(evidenceIDs, finding.ID)
		}
	}
	now := a.now()
	content, err := a.reportGenerator.Generate(ctx, report.Input{Certificate: cert, Risks: matchingRisks})
	if err != nil {
		span.RecordError(err)
		return domain.HandoffReport{}, err
	}
	report := domain.HandoffReport{
		ID:               "report_" + compactTimestamp(now),
		CertificateID:    certificateID,
		ServiceID:        cert.ServiceID,
		Summary:          content.Summary,
		Risks:            defaultStrings(content.Risks, riskTitles),
		HandoffChecklist: content.HandoffChecklist,
		RenewalSteps:     content.RenewalSteps,
		EvidenceIDs:      defaultStrings(content.EvidenceIDs, evidenceIDs),
		CreatedAt:        now,
	}
	if err := a.store.SaveReport(report); err != nil {
		span.RecordError(err)
		return domain.HandoffReport{}, err
	}
	return report, nil
}

func (a *App) startSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	if a.telemetry == nil || a.telemetry.Tracer == nil {
		return trace.NewNoopTracerProvider().Tracer("certflow").Start(ctx, name)
	}
	return a.telemetry.Tracer.Start(ctx, name)
}

func (a *App) SeedDemoData() error {
	if a.store == nil {
		return fmt.Errorf("store is required")
	}
	now := a.now()
	certs := []domain.Certificate{
		{
			ID:                "cert_demo_api",
			FingerprintSHA256: "sha256:8c8e2f2c4b6a8f01",
			SerialNumber:      "1001",
			SubjectCommonName: "api.certflow.demo",
			IssuerCommonName:  "Demo Intermediate CA",
			NotBefore:         now.Add(-80 * 24 * time.Hour),
			NotAfter:          now.Add(9 * 24 * time.Hour),
			DNSNames:          []string{"api.certflow.demo"},
			PublicKeyAlg:      "RSA",
			SignatureAlg:      "SHA256-RSA",
			Source:            "demo",
			Endpoint:          "api.certflow.demo:443",
			ServiceID:         "svc-api",
			Environment:       "prod",
			OwnerTeam:         "platform-sre",
			RenewalMethod:     "acme",
			FirstSeenAt:       now,
			LastSeenAt:        now,
		},
		{
			ID:                "cert_demo_admin",
			FingerprintSHA256: "sha256:4c155eed0f91a830",
			SerialNumber:      "1002",
			SubjectCommonName: "admin.certflow.demo",
			IssuerCommonName:  "Demo Intermediate CA",
			NotBefore:         now.Add(-20 * 24 * time.Hour),
			NotAfter:          now.Add(95 * 24 * time.Hour),
			DNSNames:          []string{"admin.certflow.demo"},
			PublicKeyAlg:      "ECDSA",
			SignatureAlg:      "ECDSA-SHA256",
			Source:            "demo",
			Endpoint:          "admin.certflow.demo:443",
			ServiceID:         "svc-admin",
			Environment:       "prod",
			FirstSeenAt:       now,
			LastSeenAt:        now,
		},
		{
			ID:                "cert_demo_docs",
			FingerprintSHA256: "sha256:e2b832aa0a91d114",
			SerialNumber:      "1003",
			SubjectCommonName: "docs.certflow.demo",
			IssuerCommonName:  "Managed Demo CA",
			NotBefore:         now.Add(-10 * 24 * time.Hour),
			NotAfter:          now.Add(180 * 24 * time.Hour),
			DNSNames:          []string{"docs.certflow.demo"},
			PublicKeyAlg:      "ECDSA",
			SignatureAlg:      "ECDSA-SHA256",
			Source:            "demo",
			Endpoint:          "docs.certflow.demo:443",
			ServiceID:         "svc-docs",
			Environment:       "prod",
			OwnerTeam:         "developer-platform",
			RenewalMethod:     "managed",
			FirstSeenAt:       now,
			LastSeenAt:        now,
		},
	}

	findings := make([]domain.RiskFinding, 0)
	for _, cert := range certs {
		findings = append(findings, risk.Evaluate(now, cert)...)
	}
	scan := domain.ScanRun{
		ID:           "scan_demo_seed",
		Name:         "offline-demo-seed",
		StartedAt:    now,
		CompletedAt:  now,
		Certificates: certs,
		Risks:        findings,
	}
	return a.store.SaveScan(scan)
}

func (a *App) ImportCertificates(source string, certs []domain.Certificate) error {
	if a.store == nil {
		return fmt.Errorf("store is required")
	}
	now := a.now()
	findings := make([]domain.RiskFinding, 0)
	for i := range certs {
		if certs[i].FirstSeenAt.IsZero() {
			certs[i].FirstSeenAt = now
		}
		certs[i].LastSeenAt = now
		findings = append(findings, risk.Evaluate(now, certs[i])...)
	}
	scan := domain.ScanRun{
		ID:           "import_" + source + "_" + compactTimestamp(now),
		Name:         "fixture-import-" + source,
		StartedAt:    now,
		CompletedAt:  now,
		Certificates: certs,
		Risks:        findings,
	}
	return a.store.SaveScan(scan)
}

func defaultStrings(values, fallback []string) []string {
	if len(values) > 0 {
		return values
	}
	return fallback
}

func compactTimestamp(t time.Time) string {
	return t.UTC().Format("20060102T150405000000000")
}
