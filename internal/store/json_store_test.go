package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/satviktalchuru/certflow-ai/internal/domain"
)

func TestJSONStorePersistsCertificatesRisksScansAndReports(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certflow.json")
	store := NewJSONStore(path)
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

	cert := domain.Certificate{
		ID:                "cert_1",
		FingerprintSHA256: "sha256:abc",
		SerialNumber:      "123",
		NotAfter:          now.Add(24 * time.Hour),
		Source:            "endpoint",
		Endpoint:          "api.example.com:443",
	}
	risk := domain.RiskFinding{
		ID:            "risk_1",
		CertificateID: "cert_1",
		Severity:      domain.SeverityCritical,
		Category:      "expiration",
		Title:         "expires soon",
		Status:        "open",
		CreatedAt:     now,
	}
	scan := domain.ScanRun{ID: "scan_1", Name: "demo", StartedAt: now, CompletedAt: now, Certificates: []domain.Certificate{cert}, Risks: []domain.RiskFinding{risk}}
	report := domain.HandoffReport{ID: "report_1", CertificateID: "cert_1", Summary: "handoff", EvidenceIDs: []string{"risk_1"}, CreatedAt: now}

	if err := store.SaveScan(scan); err != nil {
		t.Fatalf("save scan: %v", err)
	}
	if err := store.SaveReport(report); err != nil {
		t.Fatalf("save report: %v", err)
	}

	reopened := NewJSONStore(path)
	certs, err := reopened.ListCertificates()
	if err != nil {
		t.Fatalf("list certs: %v", err)
	}
	if len(certs) != 1 || certs[0].ID != "cert_1" {
		t.Fatalf("expected persisted cert, got %#v", certs)
	}

	risks, err := reopened.ListRisks()
	if err != nil {
		t.Fatalf("list risks: %v", err)
	}
	if len(risks) != 1 || risks[0].ID != "risk_1" {
		t.Fatalf("expected persisted risk, got %#v", risks)
	}

	reports, err := reopened.ListReports()
	if err != nil {
		t.Fatalf("list reports: %v", err)
	}
	if len(reports) != 1 || reports[0].ID != "report_1" {
		t.Fatalf("expected persisted report, got %#v", reports)
	}
}
