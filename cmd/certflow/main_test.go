package main

import (
	"os"
	"testing"

	"github.com/satviktalchuru/certflow-ai/internal/report"
)

func TestReportGeneratorFromEnvDefaultsToLocal(t *testing.T) {
	t.Setenv("CERTFLOW_AI_PROVIDER", "")
	t.Setenv("OPENAI_API_KEY", "")

	generator := reportGeneratorFromEnv()

	if _, ok := generator.(report.LocalGenerator); !ok {
		t.Fatalf("expected local generator, got %T", generator)
	}
}

func TestReportGeneratorFromEnvUsesOpenAIWhenConfigured(t *testing.T) {
	t.Setenv("CERTFLOW_AI_PROVIDER", "openai")
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("OPENAI_MODEL", "gpt-5.5")
	t.Setenv("OPENAI_RESPONSES_ENDPOINT", "https://example.test/v1/responses")

	generator := reportGeneratorFromEnv()

	openai, ok := generator.(report.OpenAIGenerator)
	if !ok {
		t.Fatalf("expected OpenAI generator, got %T", generator)
	}
	if openai.APIKey != "test-key" || openai.Model != "gpt-5.5" || openai.Endpoint != "https://example.test/v1/responses" {
		t.Fatalf("unexpected openai generator: %#v", openai)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
