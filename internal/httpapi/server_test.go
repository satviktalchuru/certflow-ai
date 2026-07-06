package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/satviktalchuru/certflow-ai/internal/app"
	"github.com/satviktalchuru/certflow-ai/internal/domain"
	"github.com/satviktalchuru/certflow-ai/internal/store"
)

func TestServerExposesHealthCertificatesRisksAndReports(t *testing.T) {
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	st := store.NewJSONStore(filepath.Join(t.TempDir(), "certflow.json"))
	cert := domain.Certificate{ID: "cert_1", FingerprintSHA256: "sha256:abc", NotAfter: now.Add(24 * time.Hour), Source: "endpoint", Endpoint: "api.example.com:443"}
	risk := domain.RiskFinding{ID: "risk_1", CertificateID: "cert_1", Severity: domain.SeverityCritical, Category: "expiration", Title: "Certificate expires soon", Status: "open", CreatedAt: now}
	if err := st.SaveScan(domain.ScanRun{ID: "scan_1", Name: "seed", StartedAt: now, CompletedAt: now, Certificates: []domain.Certificate{cert}, Risks: []domain.RiskFinding{risk}}); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	server := NewServer(app.New(app.Config{Store: st, Now: func() time.Time { return now }}))

	health := httptest.NewRecorder()
	server.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/v1/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("expected health 200, got %d", health.Code)
	}

	certs := httptest.NewRecorder()
	server.ServeHTTP(certs, httptest.NewRequest(http.MethodGet, "/v1/certificates", nil))
	if certs.Code != http.StatusOK {
		t.Fatalf("expected certs 200, got %d", certs.Code)
	}
	var certPayload []domain.Certificate
	if err := json.Unmarshal(certs.Body.Bytes(), &certPayload); err != nil {
		t.Fatalf("decode cert payload: %v", err)
	}
	if len(certPayload) != 1 || certPayload[0].ID != "cert_1" {
		t.Fatalf("expected cert_1 payload, got %#v", certPayload)
	}

	risks := httptest.NewRecorder()
	server.ServeHTTP(risks, httptest.NewRequest(http.MethodGet, "/v1/risks", nil))
	if risks.Code != http.StatusOK {
		t.Fatalf("expected risks 200, got %d", risks.Code)
	}

	body := bytes.NewBufferString(`{"certificate_id":"cert_1"}`)
	reports := httptest.NewRecorder()
	server.ServeHTTP(reports, httptest.NewRequest(http.MethodPost, "/v1/ai/handoff-reports", body))
	if reports.Code != http.StatusCreated {
		t.Fatalf("expected report 201, got %d: %s", reports.Code, reports.Body.String())
	}
	var report domain.HandoffReport
	if err := json.Unmarshal(reports.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if len(report.EvidenceIDs) != 1 || report.EvidenceIDs[0] != "risk_1" {
		t.Fatalf("expected evidence risk_1, got %#v", report.EvidenceIDs)
	}
}
