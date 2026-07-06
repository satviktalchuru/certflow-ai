package demo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/satviktalchuru/certflow-ai/internal/domain"
)

type TLSServices struct {
	servers []*http.Server
	targets []domain.Target
	wg      sync.WaitGroup
}

func StartTLSServices() (*TLSServices, error) {
	defs := []struct {
		name          string
		serviceID     string
		ownerTeam     string
		renewalMethod string
		validFor      time.Duration
	}{
		{name: "healthy.certflow.local", serviceID: "svc-local-healthy", ownerTeam: "platform-sre", renewalMethod: "acme", validFor: 180 * 24 * time.Hour},
		{name: "expiring.certflow.local", serviceID: "svc-local-expiring", ownerTeam: "platform-sre", renewalMethod: "manual", validFor: 9 * 24 * time.Hour},
		{name: "ownerless.certflow.local", serviceID: "svc-local-ownerless", validFor: 90 * 24 * time.Hour},
	}

	services := &TLSServices{}
	for _, def := range defs {
		cert, err := selfSignedCert(def.name, def.validFor)
		if err != nil {
			services.Close()
			return nil, err
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			services.Close()
			return nil, err
		}
		tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{cert}})
		server := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			}),
		}
		services.servers = append(services.servers, server)
		host, portText, err := net.SplitHostPort(listener.Addr().String())
		if err != nil {
			services.Close()
			return nil, err
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			services.Close()
			return nil, err
		}
		services.targets = append(services.targets, domain.Target{
			Host:          host,
			Port:          port,
			ServiceID:     def.serviceID,
			Environment:   "local",
			OwnerTeam:     def.ownerTeam,
			RenewalMethod: def.renewalMethod,
		})
		services.wg.Add(1)
		go func() {
			defer services.wg.Done()
			if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
				fmt.Printf("certflow demo service error: %v\n", err)
			}
		}()
	}
	return services, nil
}

func (s *TLSServices) Targets() []domain.Target {
	return append([]domain.Target(nil), s.targets...)
}

func (s *TLSServices) Close() {
	for _, server := range s.servers {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = server.Shutdown(ctx)
		cancel()
	}
	s.wg.Wait()
}

func selfSignedCert(name string, validFor time.Duration) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}
	notBefore := time.Now().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: name,
		},
		DNSNames:              []string{name},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
