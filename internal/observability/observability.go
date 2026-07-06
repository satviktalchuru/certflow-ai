package observability

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
	"go.opentelemetry.io/otel/trace"
)

type Config struct {
	ServiceName string
	Stdout      bool
}

type Telemetry struct {
	Tracer       trace.Tracer
	Meter        metric.Meter
	scanTargets  metric.Int64Counter
	scanFailures metric.Int64Counter
	scanDuration metric.Float64Histogram
}

func Setup(ctx context.Context, cfg Config) (*Telemetry, func(context.Context) error, error) {
	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "certflow-ai"
	}
	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		"",
		semconv.ServiceName(serviceName),
	))
	if err != nil {
		return nil, nil, err
	}

	traceProvider, traceShutdown, err := traceProvider(ctx, res, cfg.Stdout)
	if err != nil {
		return nil, nil, err
	}
	meterProvider, metricShutdown, err := meterProvider(ctx, res, cfg.Stdout)
	if err != nil {
		_ = traceShutdown(ctx)
		return nil, nil, err
	}
	otel.SetTracerProvider(traceProvider)
	otel.SetMeterProvider(meterProvider)

	meter := meterProvider.Meter("github.com/satviktalchuru/certflow-ai")
	scanTargets, err := meter.Int64Counter("certflow_scan_targets_total", metric.WithDescription("Total TLS scan targets processed"))
	if err != nil {
		return nil, nil, err
	}
	scanFailures, err := meter.Int64Counter("certflow_scan_failures_total", metric.WithDescription("Total TLS scan target failures"))
	if err != nil {
		return nil, nil, err
	}
	scanDuration, err := meter.Float64Histogram("certflow_scan_duration_seconds", metric.WithDescription("TLS scan duration in seconds"))
	if err != nil {
		return nil, nil, err
	}

	telemetry := &Telemetry{
		Tracer:       traceProvider.Tracer("github.com/satviktalchuru/certflow-ai"),
		Meter:        meter,
		scanTargets:  scanTargets,
		scanFailures: scanFailures,
		scanDuration: scanDuration,
	}
	shutdown := func(ctx context.Context) error {
		err1 := metricShutdown(ctx)
		err2 := traceShutdown(ctx)
		if err1 != nil {
			return err1
		}
		return err2
	}
	return telemetry, shutdown, nil
}

func (t *Telemetry) RecordScanResult(ctx context.Context, source string, targets, failures int, durationSeconds float64) error {
	if t == nil {
		return nil
	}
	attrs := metric.WithAttributes(attribute.String("certflow.source", source))
	t.scanTargets.Add(ctx, int64(targets), attrs)
	t.scanFailures.Add(ctx, int64(failures), attrs)
	t.scanDuration.Record(ctx, durationSeconds, attrs)
	return nil
}

func traceProvider(ctx context.Context, res *resource.Resource, stdout bool) (*sdktrace.TracerProvider, func(context.Context) error, error) {
	options := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
	}
	if stdout {
		exporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, nil, err
		}
		options = append(options, sdktrace.WithBatcher(exporter))
	}
	provider := sdktrace.NewTracerProvider(options...)
	return provider, provider.Shutdown, nil
}

func meterProvider(ctx context.Context, res *resource.Resource, stdout bool) (*sdkmetric.MeterProvider, func(context.Context) error, error) {
	options := []sdkmetric.Option{
		sdkmetric.WithResource(res),
	}
	if stdout {
		exporter, err := stdoutmetric.New()
		if err != nil {
			return nil, nil, err
		}
		reader := sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(5*time.Second))
		options = append(options, sdkmetric.WithReader(reader))
	}
	provider := sdkmetric.NewMeterProvider(options...)
	return provider, provider.Shutdown, nil
}

func SpanName(component, operation string) string {
	return fmt.Sprintf("certflow.%s.%s", component, operation)
}
