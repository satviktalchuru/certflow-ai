package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/satviktalchuru/certflow-ai/internal/domain"
	_ "modernc.org/sqlite"
)

type relationalDialect string

const (
	dialectSQLite   relationalDialect = "sqlite"
	dialectPostgres relationalDialect = "postgres"
)

type SQLiteStore struct {
	*relationalStore
}

type PostgresStore struct {
	*relationalStore
}

type relationalStore struct {
	db      *sql.DB
	dialect relationalDialect
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	store := &SQLiteStore{relationalStore: &relationalStore{db: db, dialect: dialectSQLite}}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func NewPostgresStore(dsn string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	store := &PostgresStore{relationalStore: &relationalStore{db: db, dialect: dialectPostgres}}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *relationalStore) Close() error {
	return s.db.Close()
}

func (s *relationalStore) migrate() error {
	stmts := []string{
		`create table if not exists scans (
			id text primary key,
			name text not null,
			started_at text not null,
			completed_at text not null,
			targets_json text not null,
			errors_json text not null
		)`,
		`create table if not exists certificates (
			id text primary key,
			fingerprint_sha256 text not null unique,
			serial_number text not null,
			subject_common_name text,
			issuer_common_name text,
			not_before text not null,
			not_after text not null,
			dns_names_json text not null,
			ip_addresses_json text not null,
			public_key_algorithm text,
			signature_algorithm text,
			source text not null,
			endpoint text,
			service_id text,
			environment text,
			owner_team text,
			renewal_method text,
			tags_json text not null,
			first_seen_at text not null,
			last_seen_at text not null
		)`,
		`create table if not exists scan_certificates (
			scan_id text not null,
			certificate_id text not null,
			primary key (scan_id, certificate_id)
		)`,
		`create table if not exists risks (
			id text primary key,
			certificate_id text not null,
			severity text not null,
			category text not null,
			title text not null,
			evidence_json text not null,
			status text not null,
			created_at text not null
		)`,
		`create table if not exists scan_risks (
			scan_id text not null,
			risk_id text not null,
			primary key (scan_id, risk_id)
		)`,
		`create table if not exists reports (
			id text primary key,
			service_id text,
			certificate_id text,
			summary text not null,
			risks_json text not null,
			handoff_checklist_json text not null,
			renewal_steps_json text not null,
			evidence_ids_json text not null,
			created_at text not null
		)`,
		`create index if not exists idx_certificates_not_after on certificates(not_after)`,
		`create index if not exists idx_risks_severity on risks(severity)`,
		`create index if not exists idx_risks_certificate on risks(certificate_id)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *relationalStore) SaveScan(scan domain.ScanRun) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	targetsJSON, err := marshal(scan.Targets)
	if err != nil {
		return err
	}
	errorsJSON, err := marshal(scan.Errors)
	if err != nil {
		return err
	}
	if _, err := execTx(tx, s.dialect, `insert into scans(id, name, started_at, completed_at, targets_json, errors_json)
		values(?, ?, ?, ?, ?, ?)
		on conflict(id) do update set name=excluded.name, started_at=excluded.started_at, completed_at=excluded.completed_at, targets_json=excluded.targets_json, errors_json=excluded.errors_json`,
		scan.ID, scan.Name, encodeTime(scan.StartedAt), encodeTime(scan.CompletedAt), targetsJSON, errorsJSON); err != nil {
		return err
	}

	for _, cert := range scan.Certificates {
		if err := saveCertificate(tx, s.dialect, cert); err != nil {
			return err
		}
		if _, err := execTx(tx, s.dialect, `insert into scan_certificates(scan_id, certificate_id) values(?, ?) on conflict do nothing`, scan.ID, cert.ID); err != nil {
			return err
		}
	}
	for _, risk := range scan.Risks {
		if err := saveRisk(tx, s.dialect, risk); err != nil {
			return err
		}
		if _, err := execTx(tx, s.dialect, `insert into scan_risks(scan_id, risk_id) values(?, ?) on conflict do nothing`, scan.ID, risk.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *relationalStore) SaveReport(report domain.HandoffReport) error {
	risksJSON, err := marshal(report.Risks)
	if err != nil {
		return err
	}
	checklistJSON, err := marshal(report.HandoffChecklist)
	if err != nil {
		return err
	}
	renewalJSON, err := marshal(report.RenewalSteps)
	if err != nil {
		return err
	}
	evidenceJSON, err := marshal(report.EvidenceIDs)
	if err != nil {
		return err
	}
	_, err = execDB(s.db, s.dialect, `insert into reports(id, service_id, certificate_id, summary, risks_json, handoff_checklist_json, renewal_steps_json, evidence_ids_json, created_at)
		values(?, ?, ?, ?, ?, ?, ?, ?, ?)
		on conflict(id) do update set service_id=excluded.service_id, certificate_id=excluded.certificate_id, summary=excluded.summary, risks_json=excluded.risks_json, handoff_checklist_json=excluded.handoff_checklist_json, renewal_steps_json=excluded.renewal_steps_json, evidence_ids_json=excluded.evidence_ids_json, created_at=excluded.created_at`,
		report.ID, report.ServiceID, report.CertificateID, report.Summary, risksJSON, checklistJSON, renewalJSON, evidenceJSON, encodeTime(report.CreatedAt))
	return err
}

func (s *relationalStore) ListCertificates() ([]domain.Certificate, error) {
	rows, err := s.db.Query(`select id, fingerprint_sha256, serial_number, subject_common_name, issuer_common_name, not_before, not_after, dns_names_json, ip_addresses_json, public_key_algorithm, signature_algorithm, source, endpoint, service_id, environment, owner_team, renewal_method, tags_json, first_seen_at, last_seen_at from certificates order by not_after asc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var certs []domain.Certificate
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, rows.Err()
}

func (s *relationalStore) ListRisks() ([]domain.RiskFinding, error) {
	rows, err := s.db.Query(`select id, certificate_id, severity, category, title, evidence_json, status, created_at from risks order by case severity when 'critical' then 4 when 'high' then 3 when 'medium' then 2 when 'low' then 1 else 0 end desc, created_at desc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var risks []domain.RiskFinding
	for rows.Next() {
		var risk domain.RiskFinding
		var severity string
		var evidenceJSON string
		var createdAt string
		if err := rows.Scan(&risk.ID, &risk.CertificateID, &severity, &risk.Category, &risk.Title, &evidenceJSON, &risk.Status, &createdAt); err != nil {
			return nil, err
		}
		risk.Severity = domain.Severity(severity)
		if err := unmarshal(evidenceJSON, &risk.Evidence); err != nil {
			return nil, err
		}
		risk.CreatedAt = decodeTime(createdAt)
		risks = append(risks, risk)
	}
	return risks, rows.Err()
}

func (s *relationalStore) ListReports() ([]domain.HandoffReport, error) {
	rows, err := s.db.Query(`select id, service_id, certificate_id, summary, risks_json, handoff_checklist_json, renewal_steps_json, evidence_ids_json, created_at from reports order by created_at desc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reports []domain.HandoffReport
	for rows.Next() {
		var report domain.HandoffReport
		var risksJSON, checklistJSON, renewalJSON, evidenceJSON, createdAt string
		if err := rows.Scan(&report.ID, &report.ServiceID, &report.CertificateID, &report.Summary, &risksJSON, &checklistJSON, &renewalJSON, &evidenceJSON, &createdAt); err != nil {
			return nil, err
		}
		if err := unmarshal(risksJSON, &report.Risks); err != nil {
			return nil, err
		}
		if err := unmarshal(checklistJSON, &report.HandoffChecklist); err != nil {
			return nil, err
		}
		if err := unmarshal(renewalJSON, &report.RenewalSteps); err != nil {
			return nil, err
		}
		if err := unmarshal(evidenceJSON, &report.EvidenceIDs); err != nil {
			return nil, err
		}
		report.CreatedAt = decodeTime(createdAt)
		reports = append(reports, report)
	}
	return reports, rows.Err()
}

func (s *relationalStore) ListScans() ([]domain.ScanRun, error) {
	rows, err := s.db.Query(`select id, name, started_at, completed_at, targets_json, errors_json from scans order by started_at desc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var scans []domain.ScanRun
	for rows.Next() {
		var scan domain.ScanRun
		var startedAt, completedAt, targetsJSON, errorsJSON string
		if err := rows.Scan(&scan.ID, &scan.Name, &startedAt, &completedAt, &targetsJSON, &errorsJSON); err != nil {
			return nil, err
		}
		if err := unmarshal(targetsJSON, &scan.Targets); err != nil {
			return nil, err
		}
		if err := unmarshal(errorsJSON, &scan.Errors); err != nil {
			return nil, err
		}
		scan.StartedAt = decodeTime(startedAt)
		scan.CompletedAt = decodeTime(completedAt)
		scans = append(scans, scan)
	}
	return scans, rows.Err()
}

func saveCertificate(tx *sql.Tx, dialect relationalDialect, cert domain.Certificate) error {
	dnsJSON, err := marshal(cert.DNSNames)
	if err != nil {
		return err
	}
	ipJSON, err := marshal(cert.IPAddresses)
	if err != nil {
		return err
	}
	tagsJSON, err := marshal(cert.Tags)
	if err != nil {
		return err
	}
	_, err = execTx(tx, dialect, `insert into certificates(id, fingerprint_sha256, serial_number, subject_common_name, issuer_common_name, not_before, not_after, dns_names_json, ip_addresses_json, public_key_algorithm, signature_algorithm, source, endpoint, service_id, environment, owner_team, renewal_method, tags_json, first_seen_at, last_seen_at)
		values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		on conflict(id) do update set fingerprint_sha256=excluded.fingerprint_sha256, serial_number=excluded.serial_number, subject_common_name=excluded.subject_common_name, issuer_common_name=excluded.issuer_common_name, not_before=excluded.not_before, not_after=excluded.not_after, dns_names_json=excluded.dns_names_json, ip_addresses_json=excluded.ip_addresses_json, public_key_algorithm=excluded.public_key_algorithm, signature_algorithm=excluded.signature_algorithm, source=excluded.source, endpoint=excluded.endpoint, service_id=excluded.service_id, environment=excluded.environment, owner_team=excluded.owner_team, renewal_method=excluded.renewal_method, tags_json=excluded.tags_json, last_seen_at=excluded.last_seen_at`,
		cert.ID, cert.FingerprintSHA256, cert.SerialNumber, cert.SubjectCommonName, cert.IssuerCommonName, encodeTime(cert.NotBefore), encodeTime(cert.NotAfter), dnsJSON, ipJSON, cert.PublicKeyAlg, cert.SignatureAlg, cert.Source, cert.Endpoint, cert.ServiceID, cert.Environment, cert.OwnerTeam, cert.RenewalMethod, tagsJSON, encodeTime(cert.FirstSeenAt), encodeTime(cert.LastSeenAt))
	return err
}

func saveRisk(tx *sql.Tx, dialect relationalDialect, risk domain.RiskFinding) error {
	evidenceJSON, err := marshal(risk.Evidence)
	if err != nil {
		return err
	}
	_, err = execTx(tx, dialect, `insert into risks(id, certificate_id, severity, category, title, evidence_json, status, created_at)
		values(?, ?, ?, ?, ?, ?, ?, ?)
		on conflict(id) do update set certificate_id=excluded.certificate_id, severity=excluded.severity, category=excluded.category, title=excluded.title, evidence_json=excluded.evidence_json, status=excluded.status, created_at=excluded.created_at`,
		risk.ID, risk.CertificateID, string(risk.Severity), risk.Category, risk.Title, evidenceJSON, risk.Status, encodeTime(risk.CreatedAt))
	return err
}

type certificateScanner interface {
	Scan(dest ...any) error
}

func scanCertificate(row certificateScanner) (domain.Certificate, error) {
	var cert domain.Certificate
	var dnsJSON, ipJSON, tagsJSON string
	var notBefore, notAfter, firstSeenAt, lastSeenAt string
	if err := row.Scan(&cert.ID, &cert.FingerprintSHA256, &cert.SerialNumber, &cert.SubjectCommonName, &cert.IssuerCommonName, &notBefore, &notAfter, &dnsJSON, &ipJSON, &cert.PublicKeyAlg, &cert.SignatureAlg, &cert.Source, &cert.Endpoint, &cert.ServiceID, &cert.Environment, &cert.OwnerTeam, &cert.RenewalMethod, &tagsJSON, &firstSeenAt, &lastSeenAt); err != nil {
		return domain.Certificate{}, err
	}
	if err := unmarshal(dnsJSON, &cert.DNSNames); err != nil {
		return domain.Certificate{}, err
	}
	if err := unmarshal(ipJSON, &cert.IPAddresses); err != nil {
		return domain.Certificate{}, err
	}
	if err := unmarshal(tagsJSON, &cert.Tags); err != nil {
		return domain.Certificate{}, err
	}
	cert.NotBefore = decodeTime(notBefore)
	cert.NotAfter = decodeTime(notAfter)
	cert.FirstSeenAt = decodeTime(firstSeenAt)
	cert.LastSeenAt = decodeTime(lastSeenAt)
	return cert, nil
}

func execDB(db *sql.DB, dialect relationalDialect, query string, args ...any) (sql.Result, error) {
	return db.Exec(bindPlaceholders(dialect, query), args...)
}

func execTx(tx *sql.Tx, dialect relationalDialect, query string, args ...any) (sql.Result, error) {
	return tx.Exec(bindPlaceholders(dialect, query), args...)
}

func bindPlaceholders(dialect relationalDialect, query string) string {
	if dialect != dialectPostgres {
		return query
	}
	var b strings.Builder
	placeholder := 1
	for _, r := range query {
		if r == '?' {
			fmt.Fprintf(&b, "$%d", placeholder)
			placeholder++
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func marshal(v any) (string, error) {
	if v == nil {
		return "null", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func unmarshal(s string, v any) error {
	if s == "" {
		s = "null"
	}
	return json.Unmarshal([]byte(s), v)
}

func encodeTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func decodeTime(value string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		panic(fmt.Sprintf("invalid stored time %q: %v", value, err))
	}
	return t
}
