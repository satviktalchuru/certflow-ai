package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/satviktalchuru/certflow-ai/internal/domain"
)

type JSONStore struct {
	path string
	mu   sync.Mutex
}

type snapshot struct {
	Scans        []domain.ScanRun       `json:"scans"`
	Certificates []domain.Certificate   `json:"certificates"`
	Risks        []domain.RiskFinding   `json:"risks"`
	Reports      []domain.HandoffReport `json:"reports"`
}

func NewJSONStore(path string) *JSONStore {
	return &JSONStore{path: path}
}

func (s *JSONStore) SaveScan(scan domain.ScanRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.load()
	if err != nil {
		return err
	}
	data.Scans = upsertScan(data.Scans, scan)
	for _, cert := range scan.Certificates {
		data.Certificates = upsertCertificate(data.Certificates, cert)
	}
	for _, risk := range scan.Risks {
		data.Risks = upsertRisk(data.Risks, risk)
	}
	return s.save(data)
}

func (s *JSONStore) SaveReport(report domain.HandoffReport) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.load()
	if err != nil {
		return err
	}
	data.Reports = upsertReport(data.Reports, report)
	return s.save(data)
}

func (s *JSONStore) ListCertificates() ([]domain.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.load()
	if err != nil {
		return nil, err
	}
	certs := append([]domain.Certificate(nil), data.Certificates...)
	sort.Slice(certs, func(i, j int) bool {
		return certs[i].NotAfter.Before(certs[j].NotAfter)
	})
	return certs, nil
}

func (s *JSONStore) ListRisks() ([]domain.RiskFinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.load()
	if err != nil {
		return nil, err
	}
	risks := append([]domain.RiskFinding(nil), data.Risks...)
	sort.Slice(risks, func(i, j int) bool {
		return severityRank(risks[i].Severity) > severityRank(risks[j].Severity)
	})
	return risks, nil
}

func (s *JSONStore) ListReports() ([]domain.HandoffReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.load()
	if err != nil {
		return nil, err
	}
	return append([]domain.HandoffReport(nil), data.Reports...), nil
}

func (s *JSONStore) ListScans() ([]domain.ScanRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.load()
	if err != nil {
		return nil, err
	}
	return append([]domain.ScanRun(nil), data.Scans...), nil
}

func (s *JSONStore) load() (snapshot, error) {
	var data snapshot
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return data, nil
	}
	if err != nil {
		return data, err
	}
	if len(b) == 0 {
		return data, nil
	}
	if err := json.Unmarshal(b, &data); err != nil {
		return data, err
	}
	return data, nil
}

func (s *JSONStore) save(data snapshot) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

func upsertScan(scans []domain.ScanRun, scan domain.ScanRun) []domain.ScanRun {
	for i := range scans {
		if scans[i].ID == scan.ID {
			scans[i] = scan
			return scans
		}
	}
	return append(scans, scan)
}

func upsertCertificate(certs []domain.Certificate, cert domain.Certificate) []domain.Certificate {
	for i := range certs {
		if certs[i].ID == cert.ID || certs[i].FingerprintSHA256 == cert.FingerprintSHA256 {
			certs[i] = cert
			return certs
		}
	}
	return append(certs, cert)
}

func upsertRisk(risks []domain.RiskFinding, risk domain.RiskFinding) []domain.RiskFinding {
	for i := range risks {
		if risks[i].ID == risk.ID {
			risks[i] = risk
			return risks
		}
	}
	return append(risks, risk)
}

func upsertReport(reports []domain.HandoffReport, report domain.HandoffReport) []domain.HandoffReport {
	for i := range reports {
		if reports[i].ID == report.ID {
			reports[i] = report
			return reports
		}
	}
	return append(reports, report)
}

func severityRank(severity domain.Severity) int {
	switch severity {
	case domain.SeverityCritical:
		return 4
	case domain.SeverityHigh:
		return 3
	case domain.SeverityMedium:
		return 2
	case domain.SeverityLow:
		return 1
	default:
		return 0
	}
}
