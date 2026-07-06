package demo

import (
	"context"
	"testing"
	"time"

	"github.com/satviktalchuru/certflow-ai/internal/certscan"
)

func TestStartTLSServicesProvidesScannableLocalTargets(t *testing.T) {
	services, err := StartTLSServices()
	if err != nil {
		t.Fatalf("start tls services: %v", err)
	}
	defer services.Close()

	targets := services.Targets()
	if len(targets) != 3 {
		t.Fatalf("expected 3 demo targets, got %d", len(targets))
	}

	result := certscan.Scanner{
		Timeout:            2 * time.Second,
		MaxConcurrency:     3,
		InsecureSkipVerify: true,
	}.Scan(context.Background(), targets)

	if len(result.Errors) != 0 {
		t.Fatalf("expected no scan errors, got %#v", result.Errors)
	}
	if len(result.Certificates) != 3 {
		t.Fatalf("expected 3 scanned certificates, got %d", len(result.Certificates))
	}
}
