// Package cache is the default abstractions.ProtectedCache implementation and an aggregating
// abstractions.ProtectedReadOnlyCache.
package cache

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/runsecure/hkdfguard-go/abstractions"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"go.opentelemetry.io/otel/attribute"
)

// ProtectedCache is the default abstractions.ProtectedCache. Backed by a single, already-built
// abstractions.DataEncryptionKey - every Add/AddOrUpdate encrypts through it (via the embedded
// *abstractions.ProtectedCacheBase), every Decrypt reveals through it. Add rejects a duplicate
// name even under concurrent callers (see ProtectedCacheBase.TryAddEncrypted); AddOrUpdate's
// upsert and Decrypt's reads are otherwise lock-free, so this holds up under highly concurrent
// access in every direction. Nothing here ever holds plaintext beyond the duration of a single
// Add/AddOrUpdate/Decrypt call.
//
// logger is optional (nil is a silent no-op - see diagnostics.SensitiveOperationLogged) and,
// when supplied, receives a debug log per sensitive operation and an error log per failure
// alongside the existing tracing/CacheMetrics.Operations telemetry.
type ProtectedCache struct {
	*abstractions.ProtectedCacheBase
	logger *slog.Logger
}

var _ abstractions.ProtectedCache = (*ProtectedCache)(nil)

// NewProtectedCache builds a ProtectedCache backed by dataEncryptionKey. logger may be nil.
func NewProtectedCache(dataEncryptionKey abstractions.DataEncryptionKey, logger *slog.Logger) *ProtectedCache {
	return &ProtectedCache{
		ProtectedCacheBase: abstractions.NewProtectedCacheBase(dataEncryptionKey),
		logger:             logger,
	}
}

// Add implements abstractions.ProtectedCache.
func (c *ProtectedCache) Add(name string, plaintext []byte) (err error) {
	tel := diagnostics.Cache
	_, span := tel.Tracer().Start(context.Background(), diagnostics.ActivityNames.Cache.Add)
	defer span.End()

	if tel.EnableSensitiveLogging() {
		tel.LogSensitiveOperation(span, diagnostics.ActivityNames.Cache.Add,
			attribute.String(diagnostics.AttributeNames.Name, name),
			attribute.Int(diagnostics.AttributeNames.PlaintextLength, len(plaintext)))
		diagnostics.SensitiveOperationLogged(c.logger, diagnostics.ActivityNames.Cache.Add, name)
	}

	defer func() {
		diagnostics.RecordCacheOperation(context.Background(), diagnostics.ActivityNames.Cache.Add, err == nil)
		if err != nil {
			tel.RecordException(span, err)
			diagnostics.OperationFailed(c.logger, diagnostics.ActivityNames.Cache.Add, err)
		}
	}()

	encrypted, err := c.Encrypt(plaintext)
	if err != nil {
		return err
	}

	if !c.TryAddEncrypted(name, encrypted) {
		return fmt.Errorf("cache: an item with the name %q has already been added", name)
	}

	return nil
}

// AddOrUpdate implements abstractions.ProtectedCache.
func (c *ProtectedCache) AddOrUpdate(name string, plaintext []byte) (err error) {
	tel := diagnostics.Cache
	_, span := tel.Tracer().Start(context.Background(), diagnostics.ActivityNames.Cache.AddOrUpdate)
	defer span.End()

	if tel.EnableSensitiveLogging() {
		tel.LogSensitiveOperation(span, diagnostics.ActivityNames.Cache.AddOrUpdate,
			attribute.String(diagnostics.AttributeNames.Name, name),
			attribute.Int(diagnostics.AttributeNames.PlaintextLength, len(plaintext)))
		diagnostics.SensitiveOperationLogged(c.logger, diagnostics.ActivityNames.Cache.AddOrUpdate, name)
	}

	defer func() {
		diagnostics.RecordCacheOperation(context.Background(), diagnostics.ActivityNames.Cache.AddOrUpdate, err == nil)
		if err != nil {
			tel.RecordException(span, err)
			diagnostics.OperationFailed(c.logger, diagnostics.ActivityNames.Cache.AddOrUpdate, err)
		}
	}()

	encrypted, err := c.Encrypt(plaintext)
	if err != nil {
		return err
	}

	c.SetEncrypted(name, encrypted)
	return nil
}
