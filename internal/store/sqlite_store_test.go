package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/satviktalchuru/certflow-ai/internal/domain"
)

func TestSQLiteStorePersistsCertificatesRisksScansAndReports(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certflow.db")
	st, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("new sqlite store: %v", err)
	}
	defer st.Close()

	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	cert := domain.Certificate{
		ID:                "cert_sqlite",
		FingerprintSHA256: "sha256:sqlite",
		SerialNumber:      "9001",
		NotAfter:          now.Add(24 * time.Hour),
		Source:            "endpoint",
		Endpoint:          "api.example.com:443",
		OwnerTeam:         "platform",
		RenewalMethod:     "acme",
		DNSNames:          []string{"api.example.com"},
	}
	risk := domain.RiskFinding{
		ID:            "risk_sqlite",
		CertificateID: "cert_sqlite",
		Severity:      domain.SeverityCritical,
		Category:      "expiration",
		Title:         "expires soon",
		Status:        "open",
		CreatedAt:     now,
	}
	report := domain.HandoffReport{
		ID:            "report_sqlite",
		CertificateID: "cert_sqlite",
		Summary:       "handoff",
		EvidenceIDs:   []string{"risk_sqlite"},
		CreatedAt:     now,
	}

	if err := st.SaveScan(domain.ScanRun{
		ID:           "scan_sqlite",
		Name:         "sqlite",
		StartedAt:    now,
		CompletedAt:  now,
		Certificates: []domain.Certificate{cert},
		Risks:        []domain.RiskFinding{risk},
	}); err != nil {
		t.Fatalf("save scan: %v", err)
	}
	if err := st.SaveReport(report); err != nil {
		t.Fatalf("save report: %v", err)
	}

	reopened, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("reopen sqlite store: %v", err)
	}
	defer reopened.Close()

	certs, err := reopened.ListCertificates()
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	if len(certs) != 1 || certs[0].ID != "cert_sqlite" || len(certs[0].DNSNames) != 1 {
		t.Fatalf("expected persisted certificate with DNS names, got %#v", certs)
	}

	risks, err := reopened.ListRisks()
	if err != nil {
		t.Fatalf("list risks: %v", err)
	}
	if len(risks) != 1 || risks[0].ID != "risk_sqlite" {
		t.Fatalf("expected persisted risk, got %#v", risks)
	}

	reports, err := reopened.ListReports()
	if err != nil {
		t.Fatalf("list reports: %v", err)
	}
	if len(reports) != 1 || reports[0].ID != "report_sqlite" || reports[0].EvidenceIDs[0] != "risk_sqlite" {
		t.Fatalf("expected persisted report, got %#v", reports)
	}

	scans, err := reopened.ListScans()
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	if len(scans) != 1 || scans[0].ID != "scan_sqlite" {
		t.Fatalf("expected persisted scan, got %#v", scans)
	}
}
