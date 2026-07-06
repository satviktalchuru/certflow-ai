package app

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/satviktalchuru/certflow-ai/internal/domain"
	"github.com/satviktalchuru/certflow-ai/internal/store"
)

func TestRunScanStoresCertificatesAndRisks(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	app := New(Config{
		Store:              store.NewJSONStore(filepath.Join(t.TempDir(), "certflow.json")),
		Now:                func() time.Time { return time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC) },
		InsecureSkipVerify: true,
	})

	scan, err := app.RunScan(context.Background(), "demo", []domain.Target{{
		Host: host,
		Port: port,
	}})
	if err != nil {
		t.Fatalf("run scan: %v", err)
	}
	if len(scan.Certificates) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(scan.Certificates))
	}
	if len(scan.Risks) == 0 {
		t.Fatal("expected missing owner/renewal risks")
	}

	risks, err := app.ListRisks()
	if err != nil {
		t.Fatalf("list risks: %v", err)
	}
	if len(risks) != len(scan.Risks) {
		t.Fatalf("expected persisted risks, got %#v", risks)
	}
}

func TestGenerateHandoffReportUsesStoredRiskEvidence(t *testing.T) {
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	st := store.NewJSONStore(filepath.Join(t.TempDir(), "certflow.json"))
	cert := domain.Certificate{ID: "cert_1", FingerprintSHA256: "sha256:abc", NotAfter: now.Add(24 * time.Hour), Endpoint: "api.example.com:443"}
	risk := domain.RiskFinding{ID: "risk_1", CertificateID: "cert_1", Severity: domain.SeverityCritical, Category: "expiration", Title: "Certificate expires in 1 day", Status: "open", CreatedAt: now}
	if err := st.SaveScan(domain.ScanRun{ID: "scan_1", Name: "seed", StartedAt: now, CompletedAt: now, Certificates: []domain.Certificate{cert}, Risks: []domain.RiskFinding{risk}}); err != nil {
		t.Fatalf("save seed scan: %v", err)
	}
	app := New(Config{Store: st, Now: func() time.Time { return now }})

	report, err := app.GenerateHandoffReport("cert_1")
	if err != nil {
		t.Fatalf("generate report: %v", err)
	}
	if report.CertificateID != "cert_1" {
		t.Fatalf("expected cert_1 report, got %q", report.CertificateID)
	}
	if len(report.EvidenceIDs) != 1 || report.EvidenceIDs[0] != "risk_1" {
		t.Fatalf("expected risk evidence, got %#v", report.EvidenceIDs)
	}
	if report.Summary == "" {
		t.Fatal("expected summary")
	}
}

func TestSeedDemoDataCreatesOfflineDashboardInventory(t *testing.T) {
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	app := New(Config{
		Store: store.NewJSONStore(filepath.Join(t.TempDir(), "certflow.json")),
		Now:   func() time.Time { return now },
	})

	if err := app.SeedDemoData(); err != nil {
		t.Fatalf("seed demo data: %v", err)
	}
	certs, err := app.ListCertificates()
	if err != nil {
		t.Fatalf("list certs: %v", err)
	}
	if len(certs) != 3 {
		t.Fatalf("expected 3 demo certs, got %d", len(certs))
	}
	risks, err := app.ListRisks()
	if err != nil {
		t.Fatalf("list risks: %v", err)
	}
	if len(risks) == 0 {
		t.Fatal("expected demo risks")
	}
}
