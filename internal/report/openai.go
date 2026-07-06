package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type OpenAIGenerator struct {
	APIKey   string
	Model    string
	Endpoint string
	Client   *http.Client
}

func (g OpenAIGenerator) Generate(ctx context.Context, input Input) (Content, error) {
	if strings.TrimSpace(g.APIKey) == "" {
		return Content{}, fmt.Errorf("OPENAI_API_KEY is required for OpenAI report generation")
	}
	model := g.Model
	if model == "" {
		model = "gpt-5.5"
	}
	endpoint := g.Endpoint
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1/responses"
	}
	client := g.Client
	if client == nil {
		client = http.DefaultClient
	}

	body := map[string]interface{}{
		"model": model,
		"input": []map[string]string{
			{
				"role":    "system",
				"content": "You generate certificate handoff reports from structured evidence. Do not invent facts. Cite only provided evidence IDs.",
			},
			{
				"role":    "user",
				"content": mustJSON(input),
			},
		},
		"text": map[string]interface{}{
			"format": map[string]interface{}{
				"type":   "json_schema",
				"name":   "certflow_handoff_report",
				"strict": true,
				"schema": reportSchema(),
			},
		},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return Content{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return Content{}, err
	}
	req.Header.Set("Authorization", "Bearer "+g.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return Content{}, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Content{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Content{}, fmt.Errorf("openai response status %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	var envelope struct {
		OutputText string `json:"output_text"`
	}
	if err := json.Unmarshal(responseBody, &envelope); err != nil {
		return Content{}, err
	}
	if strings.TrimSpace(envelope.OutputText) == "" {
		return Content{}, fmt.Errorf("openai response did not include output_text")
	}
	var content Content
	if err := json.Unmarshal([]byte(envelope.OutputText), &content); err != nil {
		return Content{}, err
	}
	return content, nil
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func reportSchema() map[string]interface{} {
	return map[string]interface{}{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"summary", "risks", "handoff_checklist", "renewal_steps", "evidence_ids"},
		"properties": map[string]interface{}{
			"summary":           map[string]interface{}{"type": "string"},
			"risks":             stringArraySchema(),
			"handoff_checklist": stringArraySchema(),
			"renewal_steps":     stringArraySchema(),
			"evidence_ids":      stringArraySchema(),
		},
	}
}

func stringArraySchema() map[string]interface{} {
	return map[string]interface{}{
		"type":  "array",
		"items": map[string]interface{}{"type": "string"},
	}
}
