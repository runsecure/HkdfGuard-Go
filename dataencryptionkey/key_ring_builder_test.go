package dataencryptionkey

import (
	"crypto/rand"
	"os"
	"testing"

	"github.com/runsecure/hkdfguard-go/abstractions"
)

// recordingCryptoProviderFactory delegates to a real AesGcmCryptoProviderFactory (so callers get
// a genuinely working CryptoProvider back) while recording the arguments each method was called
// with - lets KeyRingBuilder tests assert exactly what it passes through.
type recordingCryptoProviderFactory struct {
	createExpirySecondsCalls          []int
	createEphemeralExpirySecondsCalls []int
}

func (f *recordingCryptoProviderFactory) Create(wrapper abstractions.KeyWrapper, wrapped []byte, expirySeconds int) (abstractions.CryptoProvider, error) {
	f.createExpirySecondsCalls = append(f.createExpirySecondsCalls, expirySeconds)
	return cryptoProviderFactory.Create(wrapper, wrapped, expirySeconds)
}

func (f *recordingCryptoProviderFactory) CreateEphemeral(wrapper abstractions.KeyWrapper, expirySeconds int) (abstractions.CryptoProvider, error) {
	f.createEphemeralExpirySecondsCalls = append(f.createEphemeralExpirySecondsCalls, expirySeconds)
	return cryptoProviderFactory.CreateEphemeral(wrapper, expirySeconds)
}

func (f *recordingCryptoProviderFactory) CreateForPipeline(wrapper abstractions.KeyWrapper, notWrapped []byte) (abstractions.CryptoProvider, error) {
	return cryptoProviderFactory.CreateForPipeline(wrapper, notWrapped)
}

// recordingFormatProvider delegates to DefaultFormatProvider while recording whether Format was
// called.
type recordingFormatProvider struct {
	formatCalled bool
}

func (p *recordingFormatProvider) Format(value abstractions.KeyTrackingValue) string {
	p.formatCalled = true
	return DefaultFormatProvider{}.Format(value)
}

func (p *recordingFormatProvider) Parse(encrypted string) (abstractions.KeyTrackingValue, error) {
	return DefaultFormatProvider{}.Parse(encrypted)
}

func (p *recordingFormatProvider) GetMaxDecryptedLength(encrypted string) (int, error) {
	return DefaultFormatProvider{}.GetMaxDecryptedLength(encrypted)
}

func randomKeyWrapper(t *testing.T) *fakeKeyWrapper {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	return newFakeKeyWrapper(key)
}

func TestKeyRingBuilder_WithServiceName_SetsServiceName(t *testing.T) {
	b := NewKeyRingBuilder().WithServiceName("my-service")

	got, ok := b.ServiceName()
	if !ok || got != "my-service" {
		t.Errorf("ServiceName() = (%q, %v), want (\"my-service\", true)", got, ok)
	}
}

func TestKeyRingBuilder_Build_WithoutKeyWrapper_ReturnsError(t *testing.T) {
	b := NewKeyRingBuilder().
		WithCryptoProviderFactory(cryptoProviderFactory).
		WithCachedKeyExpiry(60).
		WithEphemeralKey(1)

	if _, err := b.Build(); err == nil {
		t.Error("Build() error = nil, want non-nil")
	}
}

func TestKeyRingBuilder_Build_WithoutCryptoProviderFactory_ReturnsError(t *testing.T) {
	b := NewKeyRingBuilder().
		WithKeyWrapper(randomKeyWrapper(t)).
		WithCachedKeyExpiry(60).
		WithEphemeralKey(1)

	if _, err := b.Build(); err == nil {
		t.Error("Build() error = nil, want non-nil")
	}
}

func TestKeyRingBuilder_Build_WithoutKeyFilesOrEphemeralKeys_ReturnsError(t *testing.T) {
	b := NewKeyRingBuilder().
		WithKeyWrapper(randomKeyWrapper(t)).
		WithCryptoProviderFactory(cryptoProviderFactory).
		WithCachedKeyExpiry(60)

	if _, err := b.Build(); err == nil {
		t.Error("Build() error = nil, want non-nil")
	}
}

func TestKeyRingBuilder_Build_WithoutCachedKeyExpiry_ReturnsError(t *testing.T) {
	b := NewKeyRingBuilder().
		WithKeyWrapper(randomKeyWrapper(t)).
		WithCryptoProviderFactory(cryptoProviderFactory).
		WithEphemeralKey(1)

	if _, err := b.Build(); err == nil {
		t.Error("Build() error = nil, want non-nil")
	}
}

func TestKeyRingBuilder_Build_WithCachedKeyExpiryOutOfRange_ReturnsError(t *testing.T) {
	for _, expiry := range []int{-1, 301} {
		b := NewKeyRingBuilder().
			WithKeyWrapper(randomKeyWrapper(t)).
			WithCryptoProviderFactory(cryptoProviderFactory).
			WithCachedKeyExpiry(expiry).
			WithEphemeralKey(1)

		if _, err := b.Build(); err == nil {
			t.Errorf("Build() with cachedKeyExpiry=%d error = nil, want non-nil", expiry)
		}
	}
}

func TestKeyRingBuilder_Build_WithKeyFile_RegistersVersionFromFile(t *testing.T) {
	path := writeTempFile(t, []byte("wrapped"))

	ring, err := NewKeyRingBuilder().
		WithKeyWrapper(randomKeyWrapper(t)).
		WithCryptoProviderFactory(cryptoProviderFactory).
		WithCachedKeyExpiry(60).
		WithKeyFile(1, path).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	version, err := ring.CurrentVersion()
	if err != nil || version != 1 {
		t.Errorf("CurrentVersion() = (%d, %v), want (1, nil)", version, err)
	}
}

func TestKeyRingBuilder_Build_WithMultipleKeyFiles_HighestVersionBecomesCurrent(t *testing.T) {
	path1 := writeTempFile(t, []byte("wrapped-v1"))
	path2 := writeTempFile(t, []byte("wrapped-v2"))

	ring, err := NewKeyRingBuilder().
		WithKeyWrapper(randomKeyWrapper(t)).
		WithCryptoProviderFactory(cryptoProviderFactory).
		WithCachedKeyExpiry(60).
		WithKeyFile(1, path1).
		WithKeyFile(2, path2).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	version, err := ring.CurrentVersion()
	if err != nil || version != 2 {
		t.Errorf("CurrentVersion() = (%d, %v), want (2, nil)", version, err)
	}
}

func TestKeyRingBuilder_Build_WithEphemeralKey_RegistersVersion(t *testing.T) {
	ring, err := NewKeyRingBuilder().
		WithKeyWrapper(randomKeyWrapper(t)).
		WithCryptoProviderFactory(cryptoProviderFactory).
		WithCachedKeyExpiry(60).
		WithEphemeralKey(1).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	version, err := ring.CurrentVersion()
	if err != nil || version != 1 {
		t.Errorf("CurrentVersion() = (%d, %v), want (1, nil)", version, err)
	}
}

func TestKeyRingBuilder_Build_WithEphemeralKey_ProducesAWorkingKey(t *testing.T) {
	ring, err := NewKeyRingBuilder().
		WithKeyWrapper(randomKeyWrapper(t)).
		WithCryptoProviderFactory(cryptoProviderFactory).
		WithCachedKeyExpiry(60).
		WithEphemeralKey(1).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	key, err := ring.Get(1)
	if err != nil {
		t.Fatalf("Get(1) error = %v", err)
	}

	plaintext := []byte("top secret")
	expected := append([]byte(nil), plaintext...)
	encrypted, err := key.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted := make([]byte, len(expected))
	written, err := key.Decrypt(encrypted, nil, decrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if written != len(expected) || string(decrypted) != string(expected) {
		t.Errorf("decrypted = %q (%d bytes), want %q", decrypted, written, expected)
	}
}

func TestKeyRingBuilder_Build_WithKeyFileAndHigherVersionEphemeralKey_EphemeralBecomesCurrent(t *testing.T) {
	path := writeTempFile(t, []byte("wrapped"))

	ring, err := NewKeyRingBuilder().
		WithKeyWrapper(randomKeyWrapper(t)).
		WithCryptoProviderFactory(cryptoProviderFactory).
		WithCachedKeyExpiry(60).
		WithKeyFile(1, path).
		WithEphemeralKey(2).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	version, err := ring.CurrentVersion()
	if err != nil || version != 2 {
		t.Errorf("CurrentVersion() = (%d, %v), want (2, nil)", version, err)
	}
}

func TestKeyRingBuilder_Build_UsesConfiguredFormatProvider(t *testing.T) {
	recording := &recordingFormatProvider{}

	ring, err := NewKeyRingBuilder().
		WithKeyWrapper(randomKeyWrapper(t)).
		WithCryptoProviderFactory(cryptoProviderFactory).
		WithCachedKeyExpiry(60).
		WithEphemeralKey(1).
		WithFormatProvider(recording).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if _, err := ring.CreateProtector("purpose").Encrypt("hello"); err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if !recording.formatCalled {
		t.Error("recording.formatCalled = false, want true")
	}
}

func TestKeyRingBuilder_Build_WithKeyFile_PassesCachedKeyExpiryToTheCryptoProviderFactory(t *testing.T) {
	path := writeTempFile(t, []byte("wrapped"))
	recording := &recordingCryptoProviderFactory{}

	_, err := NewKeyRingBuilder().
		WithKeyWrapper(randomKeyWrapper(t)).
		WithCryptoProviderFactory(recording).
		WithCachedKeyExpiry(123).
		WithKeyFile(1, path).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if len(recording.createExpirySecondsCalls) != 1 || recording.createExpirySecondsCalls[0] != 123 {
		t.Errorf("createExpirySecondsCalls = %v, want [123]", recording.createExpirySecondsCalls)
	}
}

func TestKeyRingBuilder_Build_WithEphemeralKey_PassesCachedKeyExpiryRatherThanVersionToTheCryptoProviderFactory(t *testing.T) {
	// Regression test: CreateEphemeral must be called with CachedKeyExpiry, not the KeyRing
	// version - a version of 1 would otherwise silently become a 1-second session lifetime.
	recording := &recordingCryptoProviderFactory{}

	_, err := NewKeyRingBuilder().
		WithKeyWrapper(randomKeyWrapper(t)).
		WithCryptoProviderFactory(recording).
		WithCachedKeyExpiry(123).
		WithEphemeralKey(42).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if len(recording.createEphemeralExpirySecondsCalls) != 1 || recording.createEphemeralExpirySecondsCalls[0] != 123 {
		t.Errorf("createEphemeralExpirySecondsCalls = %v, want [123]", recording.createEphemeralExpirySecondsCalls)
	}
}

func writeTempFile(t *testing.T, content []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "keyring-test-*")
	if err != nil {
		t.Fatalf("os.CreateTemp() error = %v", err)
	}
	defer f.Close()
	if _, err := f.Write(content); err != nil {
		t.Fatalf("f.Write() error = %v", err)
	}
	return f.Name()
}
