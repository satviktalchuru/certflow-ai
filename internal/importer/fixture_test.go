package importer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestImportAWSACMFixture(t *testing.T) {
	path := writeFixture(t, "aws.json", `{
	  "certificates": [{
	    "certificateArn": "arn:aws:acm:us-east-1:123:certificate/abc",
	    "domainName": "api.example.com",
	    "subjectAlternativeNames": ["api.example.com", "www.example.com"],
	    "issuer": "Amazon",
	    "serial": "01",
	    "notBefore": "2026-01-01T00:00:00Z",
	    "notAfter": "2026-07-20T00:00:00Z",
	    "renewalEligibility": "ELIGIBLE",
	    "ownerTeam": "platform"
	  }]
	}`)

	certs, err := ImportAWSACM(path)
	if err != nil {
		t.Fatalf("import aws acm: %v", err)
	}
	if len(certs) != 1 || certs[0].Source != "aws-acm" || certs[0].Endpoint != "api.example.com:443" {
		t.Fatalf("unexpected certs: %#v", certs)
	}
	if certs[0].RenewalMethod != "aws-acm-managed" {
		t.Fatalf("expected managed renewal method, got %q", certs[0].RenewalMethod)
	}
}

func TestImportGCPCertificateManagerFixture(t *testing.T) {
	path := writeFixture(t, "gcp.json", `{
	  "certificates": [{
	    "name": "projects/demo/locations/global/certificates/api",
	    "managed": {"domains": ["api.gcp.example.com"]},
	    "pemCertificate": "",
	    "expireTime": "2026-08-01T00:00:00Z",
	    "ownerTeam": "cloud-platform"
	  }]
	}`)

	certs, err := ImportGCPCertificateManager(path)
	if err != nil {
		t.Fatalf("import gcp certificate manager: %v", err)
	}
	if len(certs) != 1 || certs[0].Source != "gcp-certificate-manager" || certs[0].DNSNames[0] != "api.gcp.example.com" {
		t.Fatalf("unexpected certs: %#v", certs)
	}
}

func TestImportCertManagerFixture(t *testing.T) {
	path := writeFixture(t, "cert-manager.json", `{
	  "items": [{
	    "metadata": {"name": "api-cert", "namespace": "prod"},
	    "spec": {"dnsNames": ["api.k8s.example.com"], "secretName": "api-tls", "issuerRef": {"name": "letsencrypt"}},
	    "status": {"notBefore": "2026-01-01T00:00:00Z", "notAfter": "2026-09-01T00:00:00Z"}
	  }]
	}`)

	certs, err := ImportCertManager(path)
	if err != nil {
		t.Fatalf("import cert-manager: %v", err)
	}
	if len(certs) != 1 || certs[0].Source != "kubernetes-cert-manager" || certs[0].ServiceID != "prod/api-cert" {
		t.Fatalf("unexpected certs: %#v", certs)
	}
}

func writeFixture(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}
