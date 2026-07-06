package observability

import (
	"context"
	"testing"
)

func TestSetupReturnsTelemetryAndShutdown(t *testing.T) {
	telemetry, shutdown, err := Setup(context.Background(), Config{
		ServiceName: "certflow-test",
		Stdout:      false,
	})
	if err != nil {
		t.Fatalf("setup observability: %v", err)
	}
	if telemetry.Tracer == nil {
		t.Fatal("expected tracer")
	}
	if telemetry.Meter == nil {
		t.Fatal("expected meter")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func TestTelemetryRecordsScanMetrics(t *testing.T) {
	telemetry, shutdown, err := Setup(context.Background(), Config{ServiceName: "certflow-test"})
	if err != nil {
		t.Fatalf("setup observability: %v", err)
	}
	defer shutdown(context.Background())

	if err := telemetry.RecordScanResult(context.Background(), "endpoint", 3, 1, 2.5); err != nil {
		t.Fatalf("record scan result: %v", err)
	}
}
