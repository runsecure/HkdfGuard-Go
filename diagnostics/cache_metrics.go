package diagnostics

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// RecordCacheOperation counts a ProtectedCache Add/AddOrUpdate call, tagged with
// AttributeNames.OperationName (which ActivityNames.Cache constant ran) and
// AttributeNames.Result ("success" or "error").
//
// The counter is built fresh from Cache.Meter() on every call rather than cached in a package
// var: see ComponentTelemetry's own Tracer/Meter for why an instrument resolved once, early,
// can't be trusted to observe a MeterProvider registered later (e.g. by a test).
func RecordCacheOperation(ctx context.Context, operationName string, success bool) {
	counter, err := Cache.Meter().Int64Counter(
		MetricNames.Cache.Operations,
		metric.WithUnit("{operation}"),
		metric.WithDescription("Number of ProtectedCache operations, tagged by operation and result."),
	)
	if err != nil {
		return
	}

	result := "success"
	if !success {
		result = "error"
	}

	counter.Add(ctx, 1, metric.WithAttributes(
		attribute.String(AttributeNames.OperationName, operationName),
		attribute.String(AttributeNames.Result, result),
	))
}
