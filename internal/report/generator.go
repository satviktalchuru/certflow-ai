package report

import (
	"context"
	"fmt"
	"strings"

	"github.com/satviktalchuru/certflow-ai/internal/domain"
)

type Generator interface {
	Generate(context.Context, Input) (Content, error)
}

type Input struct {
	Certificate domain.Certificate
	Risks       []domain.RiskFinding
}

type Content struct {
	Summary          string   `json:"summary"`
	Risks            []string `json:"risks"`
	HandoffChecklist []string `json:"handoff_checklist"`
	RenewalSteps     []string `json:"renewal_steps"`
	EvidenceIDs      []string `json:"evidence_ids"`
}

type LocalGenerator struct{}

func (LocalGenerator) Generate(ctx context.Context, input Input) (Content, error) {
	select {
	case <-ctx.Done():
		return Content{}, ctx.Err()
	default:
	}
	owner := strings.TrimSpace(input.Certificate.OwnerTeam)
	if owner == "" {
		owner = "unassigned"
	}
	riskSummaries := make([]string, 0, len(input.Risks))
	evidenceIDs := make([]string, 0, len(input.Risks))
	for _, risk := range input.Risks {
		riskSummaries = append(riskSummaries, fmt.Sprintf("%s: %s", risk.Severity, risk.Title))
		evidenceIDs = append(evidenceIDs, risk.ID)
	}
	summary := fmt.Sprintf("Certificate %s for %s is owned by %s and has %d open CertFlow risk(s).", input.Certificate.ID, input.Certificate.Endpoint, owner, len(input.Risks))
	if len(input.Risks) == 0 {
		summary = fmt.Sprintf("Certificate %s for %s is owned by %s with no open CertFlow risks.", input.Certificate.ID, input.Certificate.Endpoint, owner)
	}
	return Content{
		Summary: summary,
		Risks:   riskSummaries,
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
	}, nil
}
