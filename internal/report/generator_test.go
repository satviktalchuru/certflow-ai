package report

import (
	"context"
	"testing"
	"time"

	"github.com/satviktalchuru/certflow-ai/internal/domain"
)

func TestLocalGeneratorCreatesEvidenceBackedContent(t *testing.T) {
	cert := domain.Certificate{
		ID:        "cert_1",
		Endpoint:  "api.example.com:443",
		OwnerTeam: "platform",
		NotAfter:  time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC),
	}
	risks := []domain.RiskFinding{{
		ID:       "risk_1",
		Severity: domain.SeverityCritical,
		Title:    "Certificate expires soon",
	}}

	content, err := LocalGenerator{}.Generate(context.Background(), Input{Certificate: cert, Risks: risks})
	if err != nil {
		t.Fatalf("generate content: %v", err)
	}
	if content.Summary == "" {
		t.Fatal("expected summary")
	}
	if len(content.Risks) != 1 || content.EvidenceIDs[0] != "risk_1" {
		t.Fatalf("expected risk and evidence, got %#v", content)
	}
	if len(content.RenewalSteps) == 0 || len(content.HandoffChecklist) == 0 {
		t.Fatalf("expected operational steps, got %#v", content)
	}
}
