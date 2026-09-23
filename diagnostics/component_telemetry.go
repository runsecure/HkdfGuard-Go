package diagnostics

import (
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// ComponentTelemetry is one component's telemetry surface: a Tracer/Meter sharing that
// component's scope name, an EnableSensitiveLogging toggle, and the RecordException/
// LogSensitiveOperation helpers every operation across the library calls through. Tracer and
// Meter are resolved from the global OTel API on every call rather than cached at construction -
// an instrument or tracer obtained from the global API stays permanently bound to whichever
// TracerProvider/MeterProvider was live when it was built, even across a later reconfiguration
// (e.g. in tests), so resolving fresh keeps this package's vars (initialized once, at program
// start) working correctly however late the caller registers its own provider.
type ComponentTelemetry struct {
	sourceName      string
	sharedFlagOwner *ComponentTelemetry

	mu                        sync.RWMutex
	ownEnableSensitiveLogging bool
}

// newComponentTelemetry constructs a ComponentTelemetry for sourceName. sharedFlagOwner, if
// non-nil, means EnableSensitiveLogging delegates to that component's own flag instead of
// keeping an independent one - e.g. Cache/DataProtection/EncryptedConfiguration all share Root's
// flag.
func newComponentTelemetry(sourceName string, sharedFlagOwner *ComponentTelemetry) *ComponentTelemetry {
	return &ComponentTelemetry{sourceName: sourceName, sharedFlagOwner: sharedFlagOwner}
}

// SourceName returns this component's Tracer/Meter scope name - e.g. "HkdfGuard.Cache".
func (c *ComponentTelemetry) SourceName() string {
	return c.sourceName
}

// Tracer returns this component's Tracer, resolved from the current global TracerProvider.
func (c *ComponentTelemetry) Tracer() trace.Tracer {
	return otel.Tracer(c.sourceName)
}

// Meter returns this component's Meter, resolved from the current global MeterProvider.
func (c *ComponentTelemetry) Meter() metric.Meter {
	return otel.Meter(c.sourceName)
}

// EnableSensitiveLogging reports whether sensitive operations should emit additional debug
// telemetry (operation metadata such as buffer lengths and identifiers). Raw key, plaintext, and
// ciphertext bytes are never logged, regardless of this setting. A component constructed with a
// sharedFlagOwner reads/writes that owner's flag instead of keeping its own.
func (c *ComponentTelemetry) EnableSensitiveLogging() bool {
	if c.sharedFlagOwner != nil {
		return c.sharedFlagOwner.EnableSensitiveLogging()
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ownEnableSensitiveLogging
}

// SetEnableSensitiveLogging sets whether sensitive operations should emit additional debug
// telemetry (see EnableSensitiveLogging).
func (c *ComponentTelemetry) SetEnableSensitiveLogging(enabled bool) {
	if c.sharedFlagOwner != nil {
		c.sharedFlagOwner.SetEnableSensitiveLogging(enabled)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.ownEnableSensitiveLogging = enabled
}

// RecordException records err on span and marks it as errored. A nil span is a no-op.
func (c *ComponentTelemetry) RecordException(span trace.Span, err error) {
	if span == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// LogSensitiveOperation emits a fixed-name (EventNames.SensitiveOperation) debug event on span
// when EnableSensitiveLogging is set, carrying operationName and every detail as attributes.
// Only pass non-sensitive metadata (lengths, identifiers, timings) as details - never raw key,
// plaintext, or ciphertext bytes.
func (c *ComponentTelemetry) LogSensitiveOperation(span trace.Span, operationName string, details ...attribute.KeyValue) {
	if span == nil || !c.EnableSensitiveLogging() {
		return
	}

	attrs := make([]attribute.KeyValue, 0, len(details)+1)
	attrs = append(attrs, attribute.String(AttributeNames.OperationName, operationName))
	attrs = append(attrs, details...)

	span.AddEvent(EventNames.SensitiveOperation, trace.WithAttributes(attrs...))
}
