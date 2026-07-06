package importer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/satviktalchuru/certflow-ai/internal/domain"
)

func ImportAWSACM(path string) ([]domain.Certificate, error) {
	var payload struct {
		Certificates []struct {
			CertificateARN          string   `json:"certificateArn"`
			DomainName              string   `json:"domainName"`
			SubjectAlternativeNames []string `json:"subjectAlternativeNames"`
			Issuer                  string   `json:"issuer"`
			Serial                  string   `json:"serial"`
			NotBefore               string   `json:"notBefore"`
			NotAfter                string   `json:"notAfter"`
			RenewalEligibility      string   `json:"renewalEligibility"`
			OwnerTeam               string   `json:"ownerTeam"`
		} `json:"certificates"`
	}
	if err := readJSON(path, &payload); err != nil {
		return nil, err
	}
	certs := make([]domain.Certificate, 0, len(payload.Certificates))
	for _, item := range payload.Certificates {
		notBefore := parseTime(item.NotBefore)
		notAfter := parseTime(item.NotAfter)
		dnsNames := item.SubjectAlternativeNames
		if len(dnsNames) == 0 && item.DomainName != "" {
			dnsNames = []string{item.DomainName}
		}
		renewal := "aws-acm-imported"
		if item.RenewalEligibility == "ELIGIBLE" {
			renewal = "aws-acm-managed"
		}
		certs = append(certs, domain.Certificate{
			ID:                stableProviderID("aws-acm", item.CertificateARN),
			FingerprintSHA256: fingerprint("aws-acm", item.CertificateARN),
			SerialNumber:      item.Serial,
			SubjectCommonName: item.DomainName,
			IssuerCommonName:  item.Issuer,
			NotBefore:         notBefore,
			NotAfter:          notAfter,
			DNSNames:          dnsNames,
			Source:            "aws-acm",
			Endpoint:          firstEndpoint(dnsNames),
			OwnerTeam:         item.OwnerTeam,
			RenewalMethod:     renewal,
			FirstSeenAt:       time.Now().UTC(),
			LastSeenAt:        time.Now().UTC(),
		})
	}
	return certs, nil
}

func ImportGCPCertificateManager(path string) ([]domain.Certificate, error) {
	var payload struct {
		Certificates []struct {
			Name    string `json:"name"`
			Managed struct {
				Domains []string `json:"domains"`
			} `json:"managed"`
			ExpireTime string `json:"expireTime"`
			OwnerTeam  string `json:"ownerTeam"`
		} `json:"certificates"`
	}
	if err := readJSON(path, &payload); err != nil {
		return nil, err
	}
	certs := make([]domain.Certificate, 0, len(payload.Certificates))
	for _, item := range payload.Certificates {
		certs = append(certs, domain.Certificate{
			ID:                stableProviderID("gcp-certificate-manager", item.Name),
			FingerprintSHA256: fingerprint("gcp-certificate-manager", item.Name),
			SerialNumber:      item.Name,
			SubjectCommonName: firstDNS(item.Managed.Domains),
			IssuerCommonName:  "Google Certificate Manager",
			NotBefore:         time.Time{},
			NotAfter:          parseTime(item.ExpireTime),
			DNSNames:          item.Managed.Domains,
			Source:            "gcp-certificate-manager",
			Endpoint:          firstEndpoint(item.Managed.Domains),
			OwnerTeam:         item.OwnerTeam,
			RenewalMethod:     "gcp-managed",
			FirstSeenAt:       time.Now().UTC(),
			LastSeenAt:        time.Now().UTC(),
		})
	}
	return certs, nil
}

func ImportCertManager(path string) ([]domain.Certificate, error) {
	var payload struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				DNSNames   []string `json:"dnsNames"`
				SecretName string   `json:"secretName"`
				IssuerRef  struct {
					Name string `json:"name"`
				} `json:"issuerRef"`
			} `json:"spec"`
			Status struct {
				NotBefore string `json:"notBefore"`
				NotAfter  string `json:"notAfter"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := readJSON(path, &payload); err != nil {
		return nil, err
	}
	certs := make([]domain.Certificate, 0, len(payload.Items))
	for _, item := range payload.Items {
		resourceID := item.Metadata.Namespace + "/" + item.Metadata.Name
		certs = append(certs, domain.Certificate{
			ID:                stableProviderID("kubernetes-cert-manager", resourceID),
			FingerprintSHA256: fingerprint("kubernetes-cert-manager", resourceID),
			SerialNumber:      resourceID,
			SubjectCommonName: firstDNS(item.Spec.DNSNames),
			IssuerCommonName:  item.Spec.IssuerRef.Name,
			NotBefore:         parseTime(item.Status.NotBefore),
			NotAfter:          parseTime(item.Status.NotAfter),
			DNSNames:          item.Spec.DNSNames,
			Source:            "kubernetes-cert-manager",
			Endpoint:          firstEndpoint(item.Spec.DNSNames),
			ServiceID:         resourceID,
			Environment:       item.Metadata.Namespace,
			RenewalMethod:     "cert-manager",
			FirstSeenAt:       time.Now().UTC(),
			LastSeenAt:        time.Now().UTC(),
			Tags: map[string]string{
				"secret_name": item.Spec.SecretName,
			},
		})
	}
	return certs, nil
}

func readJSON(path string, dest any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dest)
}

func parseTime(value string) time.Time {
	if strings.TrimSpace(value) == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(fmt.Sprintf("invalid fixture time %q: %v", value, err))
	}
	return t
}

func stableProviderID(provider, value string) string {
	sum := sha256.Sum256([]byte(provider + ":" + value))
	return "cert_" + hex.EncodeToString(sum[:8])
}

func fingerprint(provider, value string) string {
	sum := sha256.Sum256([]byte(provider + ":" + value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func firstEndpoint(names []string) string {
	if len(names) == 0 || names[0] == "" {
		return ""
	}
	return names[0] + ":443"
}

func firstDNS(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}
