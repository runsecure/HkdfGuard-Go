package dataencryptionkey

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/runsecure/hkdfguard-go/cryptosession"
)

var cryptoProviderFactory = cryptosession.AesGcmCryptoProviderFactory{}

func newTestKey(t *testing.T) *EncryptionKeyBase {
	t.Helper()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}

	provider, err := cryptoProviderFactory.Create(newFakeKeyWrapper(key), []byte("wrapped"), 60)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	return NewEncryptionKeyBase(provider)
}

func TestEncryptionKeyBase_EncryptDecrypt_RoundTrips(t *testing.T) {
	key := newTestKey(t)
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

	if written != len(expected) {
		t.Errorf("Decrypt() wrote %d bytes, want %d", written, len(expected))
	}
	if !bytes.Equal(decrypted, expected) {
		t.Errorf("decrypted = %q, want %q", decrypted, expected)
	}
}

func TestEncryptionKeyBase_EncryptDecrypt_WithAad_RoundTrips(t *testing.T) {
	key := newTestKey(t)
	plaintext := []byte("top secret")
	expected := append([]byte(nil), plaintext...)
	aad := []byte("context")

	encrypted, err := key.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted := make([]byte, len(expected))
	written, err := key.Decrypt(encrypted, aad, decrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(decrypted[:written], expected) {
		t.Errorf("decrypted = %q, want %q", decrypted[:written], expected)
	}
}

func TestEncryptionKeyBase_Decrypt_WithMismatchedAad_ReturnsError(t *testing.T) {
	key := newTestKey(t)
	encrypted, err := key.Encrypt([]byte("top secret"), []byte("context-a"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	_, err = key.Decrypt(encrypted, []byte("context-b"), make([]byte, 16))
	if err == nil {
		t.Fatal("Decrypt() error = nil, want non-nil")
	}
}

func TestEncryptionKeyBase_Encrypt_UsesProviderAllocationLength(t *testing.T) {
	key := newTestKey(t)
	plaintext := []byte("a longer plaintext value to encrypt")

	encrypted, err := key.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// AES-GCM overhead is nonce(12) + tag(16) = 28 bytes.
	if want := len(plaintext) + 28; len(encrypted) != want {
		t.Errorf("len(encrypted) = %d, want %d", len(encrypted), want)
	}
}
