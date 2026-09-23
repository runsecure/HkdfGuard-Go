package dataencryptionkey

import (
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/runsecure/hkdfguard-go/abstractions"
)

// KeyRingBuilder builds a KeyRing from wrapped-DEK files on disk, suitable for constructing once
// at startup. There is one KeyWrapper shared by every registered file - it's bound only to a
// KEK, not to any one wrapped payload, so it can reveal any number of different files' DEKs.
// Each registered file gets its own CryptoProvider (minted by the configured
// CryptoProviderFactory, bound to that file's own wrapped bytes) and becomes its own
// EncryptionKeyBase. WithEphemeralKey registers a version whose own key material is instead
// generated fresh in memory on first use - it shares the same KeyWrapper/CryptoProviderFactory,
// so no extra configuration is needed for it.
//
// Unlike the C#/Java originals, whose With* setters validate and reject out-of-range values
// immediately, every With* method here just stores its value - Build is the single place
// everything is validated, matching the fluent-builder-then-Build idiom Go client builders
// commonly use.
type KeyRingBuilder struct {
	keyFiles              map[int]string
	ephemeralVersions     []int
	keyWrapper            abstractions.KeyWrapper
	cryptoProviderFactory abstractions.CryptoProviderFactory
	formatProvider        abstractions.EncryptedFormatProvider

	serviceName     *string
	cachedKeyExpiry *int
	keyRotationDays *int
}

// NewKeyRingBuilder builds an empty KeyRingBuilder, defaulting to DefaultFormatProvider.
func NewKeyRingBuilder() *KeyRingBuilder {
	return &KeyRingBuilder{
		keyFiles:       make(map[int]string),
		formatProvider: DefaultFormatProvider{},
	}
}

// ServiceName returns the service name set via WithServiceName, and whether one was set.
func (b *KeyRingBuilder) ServiceName() (string, bool) {
	if b.serviceName == nil {
		return "", false
	}
	return *b.serviceName, true
}

// CachedKeyExpiry returns the cached key expiry set via WithCachedKeyExpiry, and whether one
// was set.
func (b *KeyRingBuilder) CachedKeyExpiry() (int, bool) {
	if b.cachedKeyExpiry == nil {
		return 0, false
	}
	return *b.cachedKeyExpiry, true
}

// KeyRotationDays returns the key rotation days set via WithKeyRotationDays, and whether one
// was set.
func (b *KeyRingBuilder) KeyRotationDays() (int, bool) {
	if b.keyRotationDays == nil {
		return 0, false
	}
	return *b.keyRotationDays, true
}

// WithServiceName sets the service name identifying this ring's KEK to the native KMS library.
func (b *KeyRingBuilder) WithServiceName(serviceName string) *KeyRingBuilder {
	b.serviceName = &serviceName
	return b
}

// WithCachedKeyExpiry sets how many seconds a revealed key may be cached in memory before it
// must be re-derived. Must be between 0 and 300 - checked by Build, not here.
func (b *KeyRingBuilder) WithCachedKeyExpiry(cachedKeyExpiry int) *KeyRingBuilder {
	b.cachedKeyExpiry = &cachedKeyExpiry
	return b
}

// WithKeyRotationDays sets how many days may pass before this ring's key must be rotated. Must
// be between 1 and 180 - checked by Build, not here.
func (b *KeyRingBuilder) WithKeyRotationDays(keyRotationDays int) *KeyRingBuilder {
	b.keyRotationDays = &keyRotationDays
	return b
}

// WithKeyWrapper supplies the KeyWrapper shared by every registered key file when Build runs.
func (b *KeyRingBuilder) WithKeyWrapper(keyWrapper abstractions.KeyWrapper) *KeyRingBuilder {
	b.keyWrapper = keyWrapper
	return b
}

// WithCryptoProviderFactory supplies the factory used to build each key file's own
// CryptoProvider, called once per registered file with the shared KeyWrapper and that file's own
// wrapped bytes.
func (b *KeyRingBuilder) WithCryptoProviderFactory(factory abstractions.CryptoProviderFactory) *KeyRingBuilder {
	b.cryptoProviderFactory = factory
	return b
}

// WithFormatProvider overrides the EncryptedFormatProvider the built KeyRing uses for
// CreateProtector. Defaults to DefaultFormatProvider.
func (b *KeyRingBuilder) WithFormatProvider(formatProvider abstractions.EncryptedFormatProvider) *KeyRingBuilder {
	b.formatProvider = formatProvider
	return b
}

// WithKeyFile registers a version whose wrapped DEK will be read from pathToFile when Build
// runs. The highest version registered across every WithKeyFile call intrinsically becomes the
// built KeyRing's CurrentVersion.
func (b *KeyRingBuilder) WithKeyFile(version int, pathToFile string) *KeyRingBuilder {
	b.keyFiles[version] = pathToFile
	return b
}

// WithEphemeralKey registers a version whose own key material is generated fresh in memory the
// first time it's used, and never written to or read from disk. The highest version registered
// across every WithKeyFile/WithEphemeralKey call intrinsically becomes the built KeyRing's
// CurrentVersion.
func (b *KeyRingBuilder) WithEphemeralKey(version int) *KeyRingBuilder {
	b.ephemeralVersions = append(b.ephemeralVersions, version)
	return b
}

// Build reads each registered key file's wrapped bytes, mints each registered ephemeral key, and
// returns a populated KeyRing.
func (b *KeyRingBuilder) Build() (*KeyRing, error) {
	if b.keyWrapper == nil {
		return nil, errors.New("dataencryptionkey: a key wrapper is required - call WithKeyWrapper first")
	}
	if b.cryptoProviderFactory == nil {
		return nil, errors.New("dataencryptionkey: a crypto provider factory is required - call WithCryptoProviderFactory first")
	}
	if len(b.keyFiles) == 0 && len(b.ephemeralVersions) == 0 {
		return nil, errors.New("dataencryptionkey: at least one key file or ephemeral key is required - call WithKeyFile or WithEphemeralKey first")
	}
	if b.cachedKeyExpiry == nil {
		return nil, errors.New("dataencryptionkey: a cached key expiry is required - call WithCachedKeyExpiry first")
	}

	cachedKeyExpiry := *b.cachedKeyExpiry
	if cachedKeyExpiry < 0 || cachedKeyExpiry > 300 {
		return nil, fmt.Errorf("dataencryptionkey: cachedKeyExpiry must be between 0 and 300 seconds, was %d", cachedKeyExpiry)
	}
	if b.keyRotationDays != nil && (*b.keyRotationDays < 1 || *b.keyRotationDays > 180) {
		return nil, fmt.Errorf("dataencryptionkey: keyRotationDays must be between 1 and 180 days, was %d", *b.keyRotationDays)
	}

	ring := NewKeyRing(b.formatProvider)

	versions := make([]int, 0, len(b.keyFiles))
	for version := range b.keyFiles {
		versions = append(versions, version)
	}
	sort.Ints(versions)

	for _, version := range versions {
		wrapped, err := os.ReadFile(b.keyFiles[version])
		if err != nil {
			return nil, err
		}

		provider, err := b.cryptoProviderFactory.Create(b.keyWrapper, wrapped, cachedKeyExpiry)
		if err != nil {
			return nil, err
		}

		if err := ring.Add(version, NewEncryptionKeyBase(provider)); err != nil {
			return nil, err
		}
	}

	for _, version := range b.ephemeralVersions {
		provider, err := b.cryptoProviderFactory.CreateEphemeral(b.keyWrapper, cachedKeyExpiry)
		if err != nil {
			return nil, err
		}

		if err := ring.Add(version, NewEncryptionKeyBase(provider)); err != nil {
			return nil, err
		}
	}

	return ring, nil
}
