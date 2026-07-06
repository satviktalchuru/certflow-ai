package report

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/satviktalchuru/certflow-ai/internal/domain"
)

func TestOpenAIGeneratorPostsStructuredOutputRequest(t *testing.T) {
	var requestBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatalf("missing auth header")
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
		  "output_text": "{\"summary\":\"AI summary\",\"risks\":[\"critical: expires soon\"],\"handoff_checklist\":[\"Confirm owner\"],\"renewal_steps\":[\"Renew cert\"],\"evidence_ids\":[\"risk_1\"]}"
		}`))
	}))
	defer server.Close()

	content, err := OpenAIGenerator{
		APIKey:   "test-key",
		Model:    "gpt-5.5",
		Endpoint: server.URL,
		Client:   server.Client(),
	}.Generate(context.Background(), Input{
		Certificate: domain.Certificate{ID: "cert_1", Endpoint: "api.example.com:443"},
		Risks:       []domain.RiskFinding{{ID: "risk_1", Severity: domain.SeverityCritical, Title: "expires soon"}},
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if requestBody["model"] != "gpt-5.5" {
		t.Fatalf("expected model in request, got %#v", requestBody["model"])
	}
	if content.Summary != "AI summary" || content.EvidenceIDs[0] != "risk_1" {
		t.Fatalf("unexpected content: %#v", content)
	}
}
