package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/satviktalchuru/certflow-ai/internal/app"
	"github.com/satviktalchuru/certflow-ai/internal/domain"
)

type Server struct {
	app    *app.App
	static http.Handler
}

func NewServer(app *app.App) *Server {
	return &Server{
		app:    app,
		static: http.FileServer(http.Dir("web/static")),
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/v1/healthz" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
