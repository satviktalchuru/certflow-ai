package certscan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/satviktalchuru/certflow-ai/internal/domain"
)

func TestScannerExtractsCertificateMetadataFromTLSEndpoint(t *testing.T) {
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

	scanner := Scanner{Timeout: 2 * time.Second, MaxConcurrency: 2, InsecureSkipVerify: true}
	result := scanner.Scan(context.Background(), []domain.Target{{
		Host:          host,
		Port:          port,
		ServiceID:     "svc-demo",
		Environment:   "test",
		OwnerTeam:     "platform",
		RenewalMethod: "demo",
	}})

	if len(result.Errors) != 0 {
		t.Fatalf("expected no scan errors, got %#v", result.Errors)
	}
	if len(result.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(result.Certificates))
	}

	cert := result.Certificates[0]
	if cert.FingerprintSHA256 == "" {
		t.Fatal("expected fingerprint")
	}
	if cert.SerialNumber == "" {
		t.Fatal("expected serial number")
	}
	if cert.Endpoint == "" {
		t.Fatal("expected endpoint")
	}
	if cert.ServiceID != "svc-demo" {
		t.Fatalf("expected service id svc-demo, got %q", cert.ServiceID)
	}
	if !cert.NotAfter.After(time.Now()) {
		t.Fatalf("expected future expiration, got %s", cert.NotAfter)
	}
}
