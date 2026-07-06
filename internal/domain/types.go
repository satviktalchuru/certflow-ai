package domain

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

type Target struct {
	Host          string            `json:"host"`
	Port          int               `json:"port"`
	ServiceID     string            `json:"service_id,omitempty"`
	Environment   string            `json:"environment,omitempty"`
	OwnerTeam     string            `json:"owner_team,omitempty"`
	RenewalMethod string            `json:"renewal_method,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
}

func (t Target) Address() string {
	port := t.Port
	if port == 0 {
		port = 443
	}
	return t.Host + ":" + itoa(port)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

type Certificate struct {
	ID                string            `json:"id"`
	FingerprintSHA256 string            `json:"fingerprint_sha256"`
	SerialNumber      string            `json:"serial_number"`
	SubjectCommonName string            `json:"subject_common_name,omitempty"`
	IssuerCommonName  string            `json:"issuer_common_name,omitempty"`
	NotBefore         time.Time         `json:"not_before"`
	NotAfter          time.Time         `json:"not_after"`
	DNSNames          []string          `json:"dns_names,omitempty"`
	IPAddresses       []string          `json:"ip_addresses,omitempty"`
	PublicKeyAlg      string            `json:"public_key_algorithm,omitempty"`
	SignatureAlg      string            `json:"signature_algorithm,omitempty"`
	Source            string            `json:"source"`
	Endpoint          string            `json:"endpoint,omitempty"`
	ServiceID         string            `json:"service_id,omitempty"`
	Environment       string            `json:"environment,omitempty"`
	OwnerTeam         string            `json:"owner_team,omitempty"`
	RenewalMethod     string            `json:"renewal_method,omitempty"`
	Tags              map[string]string `json:"tags,omitempty"`
	FirstSeenAt       time.Time         `json:"first_seen_at"`
	LastSeenAt        time.Time         `json:"last_seen_at"`
}

type RiskFinding struct {
	ID            string                 `json:"id"`
	CertificateID string                 `json:"certificate_id"`
	Severity      Severity               `json:"severity"`
	Category      string                 `json:"category"`
	Title         string                 `json:"title"`
	Evidence      map[string]interface{} `json:"evidence"`
	Status        string                 `json:"status"`
	CreatedAt     time.Time              `json:"created_at"`
}

type ScanRun struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Targets      []Target      `json:"targets"`
	StartedAt    time.Time     `json:"started_at"`
	CompletedAt  time.Time     `json:"completed_at"`
	Certificates []Certificate `json:"certificates"`
	Risks        []RiskFinding `json:"risks"`
	Errors       []ScanError   `json:"errors,omitempty"`
}

type ScanError struct {
	Target  Target `json:"target"`
	Message string `json:"message"`
}

type HandoffReport struct {
	ID               string    `json:"id"`
	ServiceID        string    `json:"service_id,omitempty"`
	CertificateID    string    `json:"certificate_id,omitempty"`
	Summary          string    `json:"summary"`
	Risks            []string  `json:"risks"`
	HandoffChecklist []string  `json:"handoff_checklist"`
	RenewalSteps     []string  `json:"renewal_steps"`
	EvidenceIDs      []string  `json:"evidence_ids"`
	CreatedAt        time.Time `json:"created_at"`
}
