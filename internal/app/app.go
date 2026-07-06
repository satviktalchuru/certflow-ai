package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/satviktalchuru/certflow-ai/internal/certscan"
	"github.com/satviktalchuru/certflow-ai/internal/domain"
	"github.com/satviktalchuru/certflow-ai/internal/risk"
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
}

type App struct {
	store              Store
	now                func() time.Time
	insecureSkipVerify bool
}

func New(cfg Config) *App {
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &App{store: cfg.Store, now: now, insecureSkipVerify: cfg.InsecureSkipVerify}
}

func (a *App) RunScan(ctx context.Context, name string, targets []domain.Target) (domain.ScanRun, error) {
	if a.store == nil {
		return domain.ScanRun{}, fmt.Errorf("store is required")
	}
	started := a.now()
	scanner := certscan.Scanner{Timeout: 5 * time.Second, MaxConcurrency: 20, InsecureSkipVerify: a.insecureSkipVerify}
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
	return scan, a.store.SaveScan(scan)
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
	certs, err := a.store.ListCertificates()
	if err != nil {
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
		return domain.HandoffReport{}, fmt.Errorf("certificate %q not found", certificateID)
	}

	allRisks, err := a.store.ListRisks()
	if err != nil {
		return domain.HandoffReport{}, err
	}
	riskTitles := make([]string, 0)
	evidenceIDs := make([]string, 0)
	for _, finding := range allRisks {
		if finding.CertificateID == certificateID {
			riskTitles = append(riskTitles, fmt.Sprintf("%s: %s", finding.Severity, finding.Title))
			evidenceIDs = append(evidenceIDs, finding.ID)
		}
	}
	now := a.now()
	report := domain.HandoffReport{
		ID:            "report_" + compactTimestamp(now),
		CertificateID: certificateID,
		ServiceID:     cert.ServiceID,
		Summary:       handoffSummary(cert, riskTitles),
		Risks:         riskTitles,
		HandoffChecklist: []string{
			"Confirm the owning team and escalation channel.",
			"Verify the renewal method and deployment path.",
			"Run a fresh CertFlow scan after renewal.",
		},
		RenewalSteps: []string{
			"Identify the certificate issuer and renewal mechanism.",
			"Renew or reissue the certificate before the risk window closes.",
			"Deploy the updated certificate to every mapped endpoint.",
			"Validate TLS handshake and certificate chain from CertFlow.",
		},
		EvidenceIDs: evidenceIDs,
		CreatedAt:   now,
	}
	if err := a.store.SaveReport(report); err != nil {
		return domain.HandoffReport{}, err
	}
	return report, nil
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

func handoffSummary(cert domain.Certificate, risks []string) string {
	owner := cert.OwnerTeam
	if strings.TrimSpace(owner) == "" {
		owner = "unassigned"
	}
	if len(risks) == 0 {
		return fmt.Sprintf("Certificate %s for %s is assigned to %s with no open CertFlow risks.", cert.ID, cert.Endpoint, owner)
	}
	return fmt.Sprintf("Certificate %s for %s needs handoff attention: %d open risk(s), owner %s.", cert.ID, cert.Endpoint, len(risks), owner)
}

func compactTimestamp(t time.Time) string {
	return t.UTC().Format("20060102T150405000000000")
}
