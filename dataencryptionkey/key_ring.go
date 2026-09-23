package dataencryptionkey

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/runsecure/hkdfguard-go/abstractions"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"go.opentelemetry.io/otel/attribute"
)

// noCurrentVersion is a sentinel meaning "no key has been added yet" - a value no real key
// version would ever use.
const noCurrentVersion = math.MinInt

// KeyRing tracks abstractions.DataEncryptionKey instances by version for highly concurrent
// workloads. Get/TryGet read under an RWMutex's read lock, so the hot read path never blocks on
// another read; Add takes the write lock, serializing registration - which only happens at
// startup/rotation, not per-operation.
//
// The ring tracks its own current version intrinsically: whichever registered version number is
// highest becomes CurrentVersion, automatically, the moment it's Added - there is no separate
// call to designate one, so it can never fall out of sync with what's actually registered.
type KeyRing struct {
	formatProvider abstractions.EncryptedFormatProvider

	mu             sync.RWMutex
	keysByVersion  map[int]abstractions.DataEncryptionKey
	currentVersion int
}

// NewKeyRing builds an empty KeyRing that formats/parses via formatProvider (see CreateProtector).
func NewKeyRing(formatProvider abstractions.EncryptedFormatProvider) *KeyRing {
	return &KeyRing{
		formatProvider: formatProvider,
		keysByVersion:  make(map[int]abstractions.DataEncryptionKey),
		currentVersion: noCurrentVersion,
	}
}

// CurrentVersion returns the highest version registered so far - what Encrypt-side operations
// (e.g. DataProtector.Encrypt) protect new data with. Returns an error if no key has been added
// yet.
func (r *KeyRing) CurrentVersion() (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.currentVersion == noCurrentVersion {
		return 0, errors.New("dataencryptionkey: no current version has been set - add a key first")
	}
	return r.currentVersion, nil
}

// Add registers key for version. If version is higher than every version registered so far, it
// intrinsically becomes the new CurrentVersion. Returns an error if a key for this version is
// already registered.
func (r *KeyRing) Add(version int, key abstractions.DataEncryptionKey) (err error) {
	tel := diagnostics.DataProtection
	_, span := tel.Tracer().Start(context.Background(), diagnostics.ActivityNames.DataProtection.KeyRingAdd)
	defer span.End()
	defer func() {
		if err != nil {
			tel.RecordException(span, err)
		}
	}()

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.keysByVersion[version]; exists {
		return fmt.Errorf("dataencryptionkey: a key for version %d is already registered", version)
	}

	r.keysByVersion[version] = key

	becameCurrent := r.currentVersion == noCurrentVersion || version > r.currentVersion
	if becameCurrent {
		r.currentVersion = version
	}

	if tel.EnableSensitiveLogging() {
		tel.LogSensitiveOperation(span, diagnostics.ActivityNames.DataProtection.KeyRingAdd,
			attribute.Int(diagnostics.AttributeNames.KeyVersion, version),
			attribute.Bool(diagnostics.AttributeNames.KeyRingBecameCurrent, becameCurrent))
	}

	return nil
}

// Get retrieves the key registered for version, returning an error if none is registered.
func (r *KeyRing) Get(version int) (abstractions.DataEncryptionKey, error) {
	r.mu.RLock()
	key, found := r.keysByVersion[version]
	r.mu.RUnlock()
	if found {
		return key, nil
	}

	notFound := fmt.Errorf("dataencryptionkey: no key is registered for version %d", version)
	tel := diagnostics.DataProtection
	_, span := tel.Tracer().Start(context.Background(), diagnostics.ActivityNames.DataProtection.KeyRingGet)
	tel.RecordException(span, notFound)
	span.End()
	return nil, notFound
}

// TryGet attempts to retrieve the key registered for version without recording telemetry on a
// miss - for the high-frequency hot path, where the overhead of a routine miss should stay
// minimal.
func (r *KeyRing) TryGet(version int) (abstractions.DataEncryptionKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	key, found := r.keysByVersion[version]
	return key, found
}

// GetCurrent retrieves CurrentVersion together with its DataEncryptionKey - what Encrypt-side
// operations (e.g. DataProtector.Encrypt) resolve fresh on every call, so they always reflect
// the latest rotation rather than a version captured once earlier.
func (r *KeyRing) GetCurrent() (version int, key abstractions.DataEncryptionKey, err error) {
	version, err = r.CurrentVersion()
	if err != nil {
		tel := diagnostics.DataProtection
		_, span := tel.Tracer().Start(context.Background(), diagnostics.ActivityNames.DataProtection.KeyRingGetCurrent)
		tel.RecordException(span, err)
		span.End()
		return 0, nil, err
	}

	key, err = r.Get(version)
	return version, key, err
}

// CreateProtector builds an abstractions.DataProtector bound to this KeyRing - the only way to
// obtain one, since dataProtector is unexported to this package. Encrypt resolves CurrentVersion
// fresh via GetCurrent on every call, and formats/parses via the EncryptedFormatProvider this
// ring was constructed with.
func (r *KeyRing) CreateProtector(name string) abstractions.DataProtector {
	return newDataProtector(name, r, r.formatProvider)
}
