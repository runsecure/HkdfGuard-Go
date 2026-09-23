package cache

import (
	"context"

	"github.com/runsecure/hkdfguard-go/abstractions"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"go.opentelemetry.io/otel/attribute"
)

// ProtectedCacheCollection aggregates multiple abstractions.ProtectedReadOnlyCache sources into
// a single read-only surface. Add registers a source and returns this same instance for fluent
// chaining (e.g. NewProtectedCacheCollection().Add(a).Add(b)). Decrypt/TryGetMaxDecryptedLength
// check each registered source in the order it was added, returning the first match. This never
// owns or writes any encrypted values of its own - Add here only registers a source, it never
// protects or stores a value - so mutation of actual cached values stays entirely a concern of
// whichever underlying source(s) actually support it (e.g. a writable *ProtectedCache mixed in
// as one of the sources).
type ProtectedCacheCollection struct {
	sources []abstractions.ProtectedReadOnlyCache
}

var _ abstractions.ProtectedReadOnlyCache = (*ProtectedCacheCollection)(nil)

// NewProtectedCacheCollection builds an empty ProtectedCacheCollection.
func NewProtectedCacheCollection() *ProtectedCacheCollection {
	return &ProtectedCacheCollection{}
}

// Add registers source as an additional lookup source, checked after every source already
// added. Returns this same ProtectedCacheCollection, for fluent chaining.
func (c *ProtectedCacheCollection) Add(source abstractions.ProtectedReadOnlyCache) *ProtectedCacheCollection {
	c.sources = append(c.sources, source)
	return c
}

// Decrypt implements abstractions.ProtectedReadOnlyCache.
func (c *ProtectedCacheCollection) Decrypt(name string, result []byte) (n int, err error) {
	tel := diagnostics.Cache
	_, span := tel.Tracer().Start(context.Background(), diagnostics.ActivityNames.Cache.Decrypt)
	defer span.End()
	defer func() {
		if err != nil {
			tel.RecordException(span, err)
		}
	}()

	if tel.EnableSensitiveLogging() {
		tel.LogSensitiveOperation(span, diagnostics.ActivityNames.Cache.Decrypt,
			attribute.String(diagnostics.AttributeNames.Name, name))
	}

	for _, source := range c.sources {
		written, decErr := source.Decrypt(name, result)
		if decErr != nil {
			return 0, decErr
		}
		if written > 0 {
			return written, nil
		}
	}

	return 0, nil
}

// TryGetMaxDecryptedLength implements abstractions.ProtectedReadOnlyCache.
func (c *ProtectedCacheCollection) TryGetMaxDecryptedLength(name string) (int, bool) {
	for _, source := range c.sources {
		if maxLength, found := source.TryGetMaxDecryptedLength(name); found {
			return maxLength, true
		}
	}
	return 0, false
}
