package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/satviktalchuru/certflow-ai/internal/app"
	"github.com/satviktalchuru/certflow-ai/internal/demo"
	"github.com/satviktalchuru/certflow-ai/internal/domain"
	"github.com/satviktalchuru/certflow-ai/internal/httpapi"
	"github.com/satviktalchuru/certflow-ai/internal/importer"
	"github.com/satviktalchuru/certflow-ai/internal/report"
	"github.com/satviktalchuru/certflow-ai/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "scan":
		err = runScan(os.Args[2:])
	case "demo-services":
		err = runDemoServices(os.Args[2:])
	case "seed":
		err = runSeed(os.Args[2:])
	case "import":
		err = runImport(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "risks":
		err = runRisks(os.Args[2:])
	case "report":
		err = runReport(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func runSeed(args []string) error {
	fs := flag.NewFlagSet("seed", flag.ExitOnError)
	dbPath := fs.String("db", "tmp/certflow.db", "path to SQLite or JSON database")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, closeStore, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer closeStore()
	if err := app.New(app.Config{Store: st, ReportGenerator: reportGeneratorFromEnv()}).SeedDemoData(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Seeded demo certificate inventory at %s\n", *dbPath)
	return nil
}

func runDemoServices(args []string) error {
	fs := flag.NewFlagSet("demo-services", flag.ExitOnError)
	targetsPath := fs.String("targets-out", "tmp/local-demo-domains.yaml", "path to write local demo targets")
	if err := fs.Parse(args); err != nil {
		return err
	}
	services, err := demo.StartTLSServices()
	if err != nil {
		return err
	}
	defer services.Close()
	if err := writeTargets(*targetsPath, services.Targets()); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Local TLS demo services running. Targets written to %s\n", *targetsPath)
	fmt.Fprintln(os.Stdout, "Scan with:")
	fmt.Fprintf(os.Stdout, "  go run ./cmd/certflow scan --targets %s --db tmp/certflow.db --insecure-skip-verify\n", *targetsPath)
	select {}
}

func runImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	provider := fs.String("provider", "", "provider: aws-acm, gcp-certificate-manager, cert-manager")
	fixturePath := fs.String("fixture", "", "path to provider fixture JSON")
	dbPath := fs.String("db", "tmp/certflow.db", "path to SQLite or JSON database")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*provider) == "" || strings.TrimSpace(*fixturePath) == "" {
		return fmt.Errorf("--provider and --fixture are required")
	}

	var (
		certs []domain.Certificate
		err   error
	)
	switch *provider {
	case "aws-acm":
		certs, err = importer.ImportAWSACM(*fixturePath)
	case "gcp-certificate-manager":
		certs, err = importer.ImportGCPCertificateManager(*fixturePath)
	case "cert-manager":
		certs, err = importer.ImportCertManager(*fixturePath)
	default:
		return fmt.Errorf("unsupported provider %q", *provider)
	}
	if err != nil {
		return err
	}
	st, closeStore, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer closeStore()
	if err := app.New(app.Config{Store: st, ReportGenerator: reportGeneratorFromEnv()}).ImportCertificates(*provider, certs); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Imported %d certificate(s) from %s into %s\n", len(certs), *provider, *dbPath)
	return nil
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	targetsPath := fs.String("targets", "fixtures/demo-domains.yaml", "path to targets YAML")
	dbPath := fs.String("db", "tmp/certflow.db", "path to SQLite or JSON database")
	name := fs.String("name", "cli-scan", "scan name")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS verification for local demos")
	if err := fs.Parse(args); err != nil {
		return err
	}
	targets, err := loadTargets(*targetsPath)
	if err != nil {
		return err
	}
	st, closeStore, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer closeStore()
	application := app.New(app.Config{Store: st, InsecureSkipVerify: *insecure, ReportGenerator: reportGeneratorFromEnv()})
	scan, err := application.RunScan(context.Background(), *name, targets)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(scan)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dbPath := fs.String("db", "tmp/certflow.db", "path to SQLite or JSON database")
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	insecure := fs.Bool("insecure-skip-verify", true, "skip TLS verification for local demo scans")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, closeStore, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer closeStore()
	application := app.New(app.Config{Store: st, InsecureSkipVerify: *insecure, ReportGenerator: reportGeneratorFromEnv()})
	server := httpapi.NewServer(application)
	log.Printf("CertFlow AI listening on http://%s", *addr)
	return http.ListenAndServe(*addr, server)
}

func runRisks(args []string) error {
	fs := flag.NewFlagSet("risks", flag.ExitOnError)
	dbPath := fs.String("db", "tmp/certflow.db", "path to SQLite or JSON database")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, closeStore, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer closeStore()
	risks, err := app.New(app.Config{Store: st, ReportGenerator: reportGeneratorFromEnv()}).ListRisks()
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(risks)
}

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	dbPath := fs.String("db", "tmp/certflow.db", "path to SQLite or JSON database")
	certID := fs.String("certificate-id", "", "certificate ID")
	outPath := fs.String("out", "", "optional markdown output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*certID) == "" {
		return fmt.Errorf("--certificate-id is required")
	}
	st, closeStore, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer closeStore()
	report, err := app.New(app.Config{Store: st, ReportGenerator: reportGeneratorFromEnv()}).GenerateHandoffReport(*certID)
	if err != nil {
		return err
	}
	markdown := reportMarkdown(report)
	if *outPath == "" {
		fmt.Print(markdown)
		return nil
	}
	return os.WriteFile(*outPath, []byte(markdown), 0o644)
}

func reportMarkdown(report domain.HandoffReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# CertFlow Handoff Report\n\n")
	fmt.Fprintf(&b, "- Report ID: `%s`\n", report.ID)
	fmt.Fprintf(&b, "- Certificate ID: `%s`\n", report.CertificateID)
	if report.ServiceID != "" {
		fmt.Fprintf(&b, "- Service ID: `%s`\n", report.ServiceID)
	}
	fmt.Fprintf(&b, "\n## Summary\n\n%s\n\n", report.Summary)
	fmt.Fprintf(&b, "## Risks\n\n")
	writeList(&b, report.Risks)
	fmt.Fprintf(&b, "\n## Handoff Checklist\n\n")
	writeList(&b, report.HandoffChecklist)
	fmt.Fprintf(&b, "\n## Renewal Steps\n\n")
	writeList(&b, report.RenewalSteps)
	fmt.Fprintf(&b, "\n## Evidence IDs\n\n")
	writeList(&b, report.EvidenceIDs)
	return b.String()
}

func writeList(b *strings.Builder, values []string) {
	if len(values) == 0 {
		b.WriteString("- None\n")
		return
	}
	for _, value := range values {
		fmt.Fprintf(b, "- %s\n", value)
	}
}

func loadTargets(path string) ([]domain.Target, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	targets := make([]domain.Target, 0)
	current := domain.Target{}
	inTarget := false

	flush := func() {
		if inTarget && current.Host != "" {
			targets = append(targets, current)
		}
		current = domain.Target{}
		inTarget = false
	}

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || line == "targets:" {
			continue
		}
		if strings.HasPrefix(line, "- ") {
			flush()
			inTarget = true
			line = strings.TrimSpace(strings.TrimPrefix(line, "- "))
			if line == "" {
				continue
			}
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch key {
		case "host":
			current.Host = value
		case "port":
			port, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", value)
			}
			current.Port = port
		case "service_id":
			current.ServiceID = value
		case "environment":
			current.Environment = value
		case "owner_team":
			current.OwnerTeam = value
		case "renewal_method":
			current.RenewalMethod = value
		}
	}
	flush()
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets found in %s", path)
	}
	return targets, nil
}

func openStore(path string) (app.Store, func(), error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".db", ".sqlite", ".sqlite3":
		st, err := store.NewSQLiteStore(path)
		if err != nil {
			return nil, func() {}, err
		}
		return st, func() { _ = st.Close() }, nil
	default:
		return store.NewJSONStore(path), func() {}, nil
	}
}

func reportGeneratorFromEnv() report.Generator {
	if strings.EqualFold(os.Getenv("CERTFLOW_AI_PROVIDER"), "openai") {
		return report.OpenAIGenerator{
			APIKey:   os.Getenv("OPENAI_API_KEY"),
			Model:    os.Getenv("OPENAI_MODEL"),
			Endpoint: os.Getenv("OPENAI_RESPONSES_ENDPOINT"),
		}
	}
	return report.LocalGenerator{}
}

func writeTargets(path string, targets []domain.Target) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("targets:\n")
	for _, target := range targets {
		fmt.Fprintf(&b, "  - host: %s\n", target.Host)
		fmt.Fprintf(&b, "    port: %d\n", target.Port)
		fmt.Fprintf(&b, "    service_id: %s\n", target.ServiceID)
		fmt.Fprintf(&b, "    environment: %s\n", target.Environment)
		if target.OwnerTeam != "" {
			fmt.Fprintf(&b, "    owner_team: %s\n", target.OwnerTeam)
		}
		if target.RenewalMethod != "" {
			fmt.Fprintf(&b, "    renewal_method: %s\n", target.RenewalMethod)
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func usage() {
	fmt.Fprintf(os.Stderr, `CertFlow AI

Usage:
  certflow scan   --targets fixtures/demo-domains.yaml --db tmp/certflow.db
  certflow demo-services --targets-out tmp/local-demo-domains.yaml
  certflow seed   --db tmp/certflow.db
  certflow import --provider aws-acm --fixture fixtures/aws-acm.json --db tmp/certflow.db
  certflow serve  --db tmp/certflow.db --addr 127.0.0.1:8080
  certflow risks  --db tmp/certflow.db
  certflow report --db tmp/certflow.db --certificate-id cert_x --out handoff.md

`)
}
