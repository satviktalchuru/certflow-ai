package certscan

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/satviktalchuru/certflow-ai/internal/domain"
	"github.com/satviktalchuru/certflow-ai/internal/observability"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type Scanner struct {
	Timeout            time.Duration
	MaxConcurrency     int
	InsecureSkipVerify bool
	Tracer             trace.Tracer
}

type Result struct {
	Certificates []domain.Certificate
	Errors       []domain.ScanError
}

func (s Scanner) Scan(ctx context.Context, targets []domain.Target) Result {
	ctx, span := s.startSpan(ctx, observability.SpanName("scanner", "scan"))
	span.SetAttributes(attribute.Int("certflow.scan.targets", len(targets)))
	defer span.End()

	timeout := s.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	maxConcurrency := s.MaxConcurrency
	if maxConcurrency <= 0 {
		maxConcurrency = 10
	}

	jobs := make(chan domain.Target)
	results := make(chan scanOneResult)
	var wg sync.WaitGroup

	for i := 0; i < maxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				results <- s.scanOne(ctx, timeout, target)
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, target := range targets {
			select {
			case <-ctx.Done():
				return
			case jobs <- target:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	out := Result{}
	for result := range results {
		if result.err != nil {
			out.Errors = append(out.Errors, domain.ScanError{Target: result.target, Message: result.err.Error()})
			continue
		}
		out.Certificates = append(out.Certificates, result.cert)
	}
	span.SetAttributes(
		attribute.Int("certflow.scan.certificates", len(out.Certificates)),
		attribute.Int("certflow.scan.errors", len(out.Errors)),
	)
	return out
}

type scanOneResult struct {
	target domain.Target
	cert   domain.Certificate
	err    error
}

func (s Scanner) scanOne(ctx context.Context, timeout time.Duration, target domain.Target) scanOneResult {
	ctx, span := s.startSpan(ctx, observability.SpanName("scanner", "target"))
	span.SetAttributes(
		attribute.String("certflow.target.host", target.Host),
		attribute.Int("certflow.target.port", target.Port),
		attribute.String("certflow.service_id", target.ServiceID),
	)
	defer span.End()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			ServerName:         target.Host,
			InsecureSkipVerify: s.InsecureSkipVerify,
		},
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialer.DialContext(scanCtx, "tcp", address(target))
	if err != nil {
		span.RecordError(err)
		return scanOneResult{target: target, err: err}
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		span.RecordError(ErrNoPeerCertificate)
		return scanOneResult{target: target, err: ErrNoPeerCertificate}
	}
	leaf := state.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	now := time.Now().UTC()

	cert := domain.Certificate{
		ID:                "cert_" + hex.EncodeToString(sum[:8]),
		FingerprintSHA256: "sha256:" + hex.EncodeToString(sum[:]),
		SerialNumber:      leaf.SerialNumber.String(),
		SubjectCommonName: leaf.Subject.CommonName,
		IssuerCommonName:  leaf.Issuer.CommonName,
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
		DNSNames:          append([]string(nil), leaf.DNSNames...),
		Source:            "endpoint",
		Endpoint:          address(target),
		ServiceID:         target.ServiceID,
		Environment:       target.Environment,
		OwnerTeam:         target.OwnerTeam,
		RenewalMethod:     target.RenewalMethod,
		Tags:              target.Tags,
		PublicKeyAlg:      leaf.PublicKeyAlgorithm.String(),
		SignatureAlg:      leaf.SignatureAlgorithm.String(),
		FirstSeenAt:       now,
		LastSeenAt:        now,
	}
	for _, ip := range leaf.IPAddresses {
		cert.IPAddresses = append(cert.IPAddresses, ip.String())
	}

	return scanOneResult{target: target, cert: cert}
}

func (s Scanner) startSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	if s.Tracer == nil {
		return trace.NewNoopTracerProvider().Tracer("certflow").Start(ctx, name)
	}
	return s.Tracer.Start(ctx, name)
}

func address(target domain.Target) string {
	port := target.Port
	if port == 0 {
		port = 443
	}
	return net.JoinHostPort(target.Host, strconv.Itoa(port))
}

type noPeerCertificateError struct{}

func (noPeerCertificateError) Error() string { return "tls endpoint returned no peer certificate" }

var ErrNoPeerCertificate error = noPeerCertificateError{}
