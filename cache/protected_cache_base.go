package cache

import (
	"context"
	"strings"
	"sync"

	"github.com/runsecure/hkdfguard-go/abstractions"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"go.opentelemetry.io/otel/attribute"
)

// ProtectedCacheBase provides shared ProtectedReadOnlyCache plumbing for every cache in this
// library: a single DataEncryptionKey, a case-insensitively-keyed concurrent map of encrypted
// bytes, and the encrypt/decrypt/telemetry logic every concrete cache needs. Decrypt/
// TryGetMaxDecryptedLength fall back to TryPopulate on a miss before giving up - nil (the
// default) means nothing to pull from, but a cache backed by an external source (e.g. a remote
// secret store) sets it to fetch the plaintext value and encrypt it into the cache on demand, so
// nothing here ever holds plaintext beyond the duration of a single call.
//
// Unlike the C#/Java originals, which use inheritance (a subclass overrides TryPopulate), Go has
// no virtual dispatch through embedding, so TryPopulate is a settable func field instead - a
// concrete cache type embeds *ProtectedCacheBase and sets the field in its own constructor.
type ProtectedCacheBase struct {
	dataEncryptionKey abstractions.DataEncryptionKey

	mu   sync.RWMutex
	data map[string][]byte

	// TryPopulate is called when name isn't already cached, before Decrypt/
	// TryGetMaxDecryptedLength give up. Nil (the default) means "nothing to pull from" - always
	// treated as returning false.
	TryPopulate func(name string) bool
}

var _ ProtectedReadOnlyCache = (*ProtectedCacheBase)(nil)

// NewProtectedCacheBase builds a ProtectedCacheBase backed by dataEncryptionKey, with no
// TryPopulate hook (set the field afterward if one is needed).
func NewProtectedCacheBase(dataEncryptionKey abstractions.DataEncryptionKey) *ProtectedCacheBase {
	return &ProtectedCacheBase{
		dataEncryptionKey: dataEncryptionKey,
		data:              make(map[string][]byte),
	}
}

// cacheKey normalizes name for case-insensitive lookup/storage - an approximation of
// OrdinalIgnoreCase good enough for the ASCII cache/service names this library expects.
func cacheKey(name string) string {
	return strings.ToLower(name)
}

// Decrypt implements ProtectedReadOnlyCache.
func (c *ProtectedCacheBase) Decrypt(name string, result []byte) (n int, err error) {
	tel := diagnostics.Root
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

	encrypted, found := c.tryGetEncrypted(name)
	if !found {
		return 0, nil
	}

	return c.dataEncryptionKey.Decrypt(encrypted, nil, result)
}

// TryGetMaxDecryptedLength implements ProtectedReadOnlyCache.
func (c *ProtectedCacheBase) TryGetMaxDecryptedLength(name string) (int, bool) {
	encrypted, found := c.tryGetEncrypted(name)
	if !found {
		return 0, false
	}
	return len(encrypted), true
}

func (c *ProtectedCacheBase) tryGetEncrypted(name string) ([]byte, bool) {
	key := cacheKey(name)

	c.mu.RLock()
	encrypted, found := c.data[key]
	c.mu.RUnlock()
	if found {
		return encrypted, true
	}

	if c.TryPopulate == nil || !c.TryPopulate(name) {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	encrypted, found = c.data[key]
	return encrypted, found
}

// SetEncrypted stores encrypted under name, keyed case-insensitively. Exported for concrete
// cache types (e.g. this package's own DefaultProtectedCache Add/AddOrUpdate) embedding
// *ProtectedCacheBase to populate directly - not meant for other callers.
func (c *ProtectedCacheBase) SetEncrypted(name string, encrypted []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[cacheKey(name)] = encrypted
}

// TryAddEncrypted stores encrypted under name only if name isn't already present, reporting
// whether the store happened. Exported for the same reason as SetEncrypted.
func (c *ProtectedCacheBase) TryAddEncrypted(name string, encrypted []byte) bool {
	key := cacheKey(name)

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.data[key]; exists {
		return false
	}
	c.data[key] = encrypted
	return true
}

// Encrypt encrypts plaintext through this cache's DataEncryptionKey. Exported for the same
// reason as SetEncrypted.
func (c *ProtectedCacheBase) Encrypt(plaintext []byte) ([]byte, error) {
	return c.dataEncryptionKey.Encrypt(plaintext, nil)
}
