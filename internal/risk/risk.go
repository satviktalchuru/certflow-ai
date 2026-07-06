package risk

import (
	"fmt"
	"strings"
	"time"

	"github.com/satviktalchuru/certflow-ai/internal/domain"
)

func Evaluate(now time.Time, cert domain.Certificate) []domain.RiskFinding {
	findings := make([]domain.RiskFinding, 0, 3)
	days := int(cert.NotAfter.Sub(now).Hours() / 24)

	if days <= 14 {
		findings = append(findings, finding(now, cert, domain.SeverityCritical, "expiration",
			fmt.Sprintf("Certificate expires in %d days", days),
			map[string]interface{}{
				"not_after":      cert.NotAfter,
				"days_remaining": days,
				"endpoint":       cert.Endpoint,
			}))
	} else if days <= 30 {
		findings = append(findings, finding(now, cert, domain.SeverityHigh, "expiration",
			fmt.Sprintf("Certificate expires in %d days", days),
			map[string]interface{}{
				"not_after":      cert.NotAfter,
				"days_remaining": days,
				"endpoint":       cert.Endpoint,
			}))
	} else if days <= 60 {
		findings = append(findings, finding(now, cert, domain.SeverityMedium, "expiration",
			fmt.Sprintf("Certificate expires in %d days", days),
			map[string]interface{}{
				"not_after":      cert.NotAfter,
				"days_remaining": days,
				"endpoint":       cert.Endpoint,
			}))
	}

	if strings.TrimSpace(cert.OwnerTeam) == "" {
		findings = append(findings, finding(now, cert, domain.SeverityHigh, "ownership",
			"Certificate has no owner team",
			map[string]interface{}{
				"endpoint":   cert.Endpoint,
				"service_id": cert.ServiceID,
			}))
	}

	if strings.TrimSpace(cert.RenewalMethod) == "" {
		findings = append(findings, finding(now, cert, domain.SeverityMedium, "renewal",
			"Certificate renewal method is unknown",
			map[string]interface{}{
				"endpoint": cert.Endpoint,
				"source":   cert.Source,
			}))
	}

	return findings
}

func finding(now time.Time, cert domain.Certificate, severity domain.Severity, category, title string, evidence map[string]interface{}) domain.RiskFinding {
	return domain.RiskFinding{
		ID:            stableRiskID(cert.ID, category),
		CertificateID: cert.ID,
		Severity:      severity,
		Category:      category,
		Title:         title,
		Evidence:      evidence,
		Status:        "open",
		CreatedAt:     now,
	}
}

func stableRiskID(certID, category string) string {
	certID = strings.TrimPrefix(certID, "cert_")
	if certID == "" {
		certID = "unknown"
	}
	return "risk_" + certID + "_" + category
}
