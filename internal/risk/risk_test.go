package risk

import (
	"testing"
	"time"

	"github.com/satviktalchuru/certflow-ai/internal/domain"
)

func TestEvaluateFlagsCriticalProductionCertificateExpiringSoon(t *testing.T) {
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	cert := domain.Certificate{
		ID:            "cert_1",
		NotAfter:      now.Add(9 * 24 * time.Hour),
		DNSNames:      []string{"api.example.com"},
		Source:        "endpoint",
		Endpoint:      "api.example.com:443",
		OwnerTeam:     "platform-sre",
		ServiceID:     "svc-api",
		RenewalMethod: "acme",
	}

	findings := Evaluate(now, cert)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].Severity != domain.SeverityCritical {
		t.Fatalf("expected critical severity, got %q", findings[0].Severity)
	}
	if findings[0].Category != "expiration" {
		t.Fatalf("expected expiration category, got %q", findings[0].Category)
	}
	if findings[0].CertificateID != "cert_1" {
		t.Fatalf("expected certificate id cert_1, got %q", findings[0].CertificateID)
	}
}

func TestEvaluateFlagsMissingOwnerAndUnknownRenewal(t *testing.T) {
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	cert := domain.Certificate{
		ID:       "cert_2",
		NotAfter: now.Add(90 * 24 * time.Hour),
		DNSNames: []string{"admin.example.com"},
		Source:   "endpoint",
		Endpoint: "admin.example.com:443",
	}

	findings := Evaluate(now, cert)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %#v", len(findings), findings)
	}
	categories := map[string]domain.Severity{}
	for _, finding := range findings {
		categories[finding.Category] = finding.Severity
	}
	if categories["ownership"] != domain.SeverityHigh {
		t.Fatalf("expected high ownership risk, got %q", categories["ownership"])
	}
	if categories["renewal"] != domain.SeverityMedium {
		t.Fatalf("expected medium renewal risk, got %q", categories["renewal"])
	}
}

func TestEvaluateReturnsNoFindingsForHealthyCertificate(t *testing.T) {
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	cert := domain.Certificate{
		ID:            "cert_3",
		NotAfter:      now.Add(180 * 24 * time.Hour),
		DNSNames:      []string{"healthy.example.com"},
		Source:        "endpoint",
		Endpoint:      "healthy.example.com:443",
		OwnerTeam:     "platform-sre",
		ServiceID:     "svc-healthy",
		RenewalMethod: "acme",
	}

	findings := Evaluate(now, cert)

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}
