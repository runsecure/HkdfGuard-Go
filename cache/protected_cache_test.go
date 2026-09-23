package cache

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/runsecure/hkdfguard-go/abstractions"
	"github.com/runsecure/hkdfguard-go/cryptosession"
	"github.com/runsecure/hkdfguard-go/dataencryptionkey"
)

// fakeKeyWrapper always reveals the same fixed key - isolates these tests from any real native
// KMS machinery while still exercising real AES-GCM via a real cryptosession.AesGcmCryptoProvider.
type fakeKeyWrapper struct {
	key []byte
}

func (w *fakeKeyWrapper) Encrypt(plaintext []byte, result []byte) (int, error) {
	panic("fakeKeyWrapper only supports Decrypt")
}

func (w *fakeKeyWrapper) Decrypt(wrapped []byte, result []byte) (int, error) {
	return copy(result, w.key), nil
}

func (w *fakeKeyWrapper) GenerateAndWrap(result []byte) (int, error) {
	return copy(result, w.key), nil
}

func newTestDataEncryptionKey(t *testing.T) abstractions.DataEncryptionKey {
	t.Helper()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}

	factory := cryptosession.AesGcmCryptoProviderFactory{}
	provider, err := factory.Create(&fakeKeyWrapper{key: key}, []byte("wrapped"), 60)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	return dataencryptionkey.NewEncryptionKeyBase(provider)
}

func TestProtectedCache_Add_EncryptsAndStores(t *testing.T) {
	sut := NewProtectedCache(newTestDataEncryptionKey(t), nil)
	plaintext := []byte("top secret")
	expected := append([]byte(nil), plaintext...)

	if err := sut.Add("name", plaintext); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	result := make([]byte, len(expected))
	written, err := sut.Decrypt("name", result)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if written != len(expected) || !bytes.Equal(result, expected) {
		t.Errorf("Decrypt() = %q (%d bytes), want %q", result, written, expected)
	}
}

func TestProtectedCache_Add_DuplicateName_ReturnsError(t *testing.T) {
	sut := NewProtectedCache(newTestDataEncryptionKey(t), nil)
	if err := sut.Add("name", []byte("first")); err != nil {
		t.Fatalf("first Add() error = %v", err)
	}

	if err := sut.Add("name", []byte("second")); err == nil {
		t.Error("second Add() error = nil, want non-nil")
	}
}

func TestProtectedCache_Add_DuplicateName_IsCaseInsensitive(t *testing.T) {
	sut := NewProtectedCache(newTestDataEncryptionKey(t), nil)
	if err := sut.Add("Name", []byte("first")); err != nil {
		t.Fatalf("first Add() error = %v", err)
	}

	if err := sut.Add("name", []byte("second")); err == nil {
		t.Error("second Add() error = nil, want non-nil")
	}
}

func TestProtectedCache_AddOrUpdate_ReplacesExistingValue(t *testing.T) {
	sut := NewProtectedCache(newTestDataEncryptionKey(t), nil)
	if err := sut.AddOrUpdate("name", []byte("first")); err != nil {
		t.Fatalf("first AddOrUpdate() error = %v", err)
	}
	if err := sut.AddOrUpdate("name", []byte("second")); err != nil {
		t.Fatalf("second AddOrUpdate() error = %v", err)
	}

	result := make([]byte, len("second"))
	written, err := sut.Decrypt("name", result)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if string(result[:written]) != "second" {
		t.Errorf("Decrypt() = %q, want %q", result[:written], "second")
	}
}

func TestProtectedCache_Decrypt_MissingName_ReturnsZero(t *testing.T) {
	sut := NewProtectedCache(newTestDataEncryptionKey(t), nil)

	written, err := sut.Decrypt("missing", make([]byte, 16))
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if written != 0 {
		t.Errorf("Decrypt() = %d, want 0", written)
	}
}

func TestProtectedCache_TryGetMaxDecryptedLength_PresentName_ReturnsEncryptedLength(t *testing.T) {
	sut := NewProtectedCache(newTestDataEncryptionKey(t), nil)
	if err := sut.Add("name", []byte("top secret")); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	maxLength, found := sut.TryGetMaxDecryptedLength("name")
	if !found {
		t.Fatal("TryGetMaxDecryptedLength() found = false, want true")
	}
	if maxLength < len("top secret") {
		t.Errorf("TryGetMaxDecryptedLength() = %d, want >= %d", maxLength, len("top secret"))
	}
}
