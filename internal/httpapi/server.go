package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/satviktalchuru/certflow-ai/internal/app"
	"github.com/satviktalchuru/certflow-ai/internal/domain"
	"github.com/satviktalchuru/certflow-ai/internal/observability"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type Server struct {
	app       *app.App
	static    http.Handler
	telemetry *observability.Telemetry
}

func NewServer(app *app.App) *Server {
	return NewServerWithTelemetry(app, nil)
}

func NewServerWithTelemetry(app *app.App, telemetry *observability.Telemetry) *Server {
	return &Server{
		app:       app,
		static:    http.FileServer(http.Dir("web/static")),
		telemetry: telemetry,
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, span := s.startSpan(r, observability.SpanName("http", "request"))
	span.SetAttributes(
		attribute.String("http.request.method", r.Method),
		attribute.String("url.path", r.URL.Path),
	)
	defer span.End()
	r = r.WithContext(ctx)

	switch {
	case r.URL.Path == "/v1/healthz" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case r.URL.Path == "/v1/openapi.json" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, openAPISpec())
	case r.URL.Path == "/v1/certificates" && r.Method == http.MethodGet:
		s.listCertificates(w)
	case r.URL.Path == "/v1/risks" && r.Method == http.MethodGet:
		s.listRisks(w)
	case r.URL.Path == "/v1/scans" && r.Method == http.MethodGet:
		s.listScans(w)
	case r.URL.Path == "/v1/scans" && r.Method == http.MethodPost:
		s.createScan(w, r)
	case r.URL.Path == "/v1/ai/handoff-reports" && r.Method == http.MethodPost:
		s.createReport(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/"):
		writeError(w, http.StatusNotFound, "endpoint not found")
	default:
		s.static.ServeHTTP(w, r)
	}
}

func (s *Server) startSpan(r *http.Request, name string) (context.Context, trace.Span) {
	if s.telemetry == nil || s.telemetry.Tracer == nil {
		return trace.NewNoopTracerProvider().Tracer("certflow").Start(r.Context(), name)
	}
	return s.telemetry.Tracer.Start(r.Context(), name)
}

func (s *Server) listCertificates(w http.ResponseWriter) {
	certs, err := s.app.ListCertificates()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, certs)
}

func (s *Server) listRisks(w http.ResponseWriter) {
	risks, err := s.app.ListRisks()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, risks)
}

func (s *Server) listScans(w http.ResponseWriter) {
	scans, err := s.app.ListScans()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string          `json:"name"`
		Targets []domain.Target `json:"targets"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		req.Name = "api-scan"
	}
	if len(req.Targets) == 0 {
		writeError(w, http.StatusBadRequest, "at least one target is required")
		return
	}
	scan, err := s.app.RunScan(r.Context(), req.Name, req.Targets)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, scan)
}

func (s *Server) createReport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CertificateID string `json:"certificate_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.CertificateID) == "" {
		writeError(w, http.StatusBadRequest, "certificate_id is required")
		return
	}
	report, err := s.app.GenerateHandoffReport(req.CertificateID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, report)
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func openAPISpec() map[string]interface{} {
	return map[string]interface{}{
		"openapi": "3.1.0",
		"info": map[string]interface{}{
			"title":       "CertFlow AI API",
			"version":     "0.1.0",
			"description": "Backend-first certificate reliability API for scans, inventory, risks, and handoff reports.",
		},
		"paths": map[string]interface{}{
			"/v1/healthz": map[string]interface{}{
				"get": op("Health check", "Returns API health status."),
			},
			"/v1/openapi.json": map[string]interface{}{
				"get": op("OpenAPI spec", "Returns this OpenAPI document."),
			},
			"/v1/certificates": map[string]interface{}{
				"get": op("List certificates", "Returns certificate inventory sorted by expiration."),
			},
			"/v1/risks": map[string]interface{}{
				"get": op("List risks", "Returns deterministic certificate risk findings."),
			},
			"/v1/scans": map[string]interface{}{
				"get":  op("List scans", "Returns historical scan runs."),
				"post": op("Create scan", "Runs a certificate scan for explicit targets."),
			},
			"/v1/ai/handoff-reports": map[string]interface{}{
				"post": op("Create handoff report", "Generates an evidence-backed handoff report for a certificate."),
			},
		},
	}
}

func op(summary, description string) map[string]interface{} {
	return map[string]interface{}{
		"summary":     summary,
		"description": description,
		"responses": map[string]interface{}{
			"200": map[string]interface{}{"description": "OK"},
			"201": map[string]interface{}{"description": "Created"},
			"400": map[string]interface{}{"description": "Bad request"},
			"500": map[string]interface{}{"description": "Internal server error"},
		},
	}
}
