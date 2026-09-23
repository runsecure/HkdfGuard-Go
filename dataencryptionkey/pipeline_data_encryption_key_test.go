package dataencryptionkey

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func newTestPipelineKey(t *testing.T, dek []byte) *PipelineDataEncryptionKey {
	t.Helper()

	if dek == nil {
		dek = make([]byte, dekLength)
		if _, err := rand.Read(dek); err != nil {
			t.Fatalf("rand.Read() error = %v", err)
		}
	}

	provider, err := cryptoProviderFactory.CreateForPipeline(dummyKeyWrapper{}, dek)
	if err != nil {
		t.Fatalf("CreateForPipeline() error = %v", err)
	}

	return newPipelineDataEncryptionKey(provider, dek)
}

func TestPipelineDataEncryptionKey_AsBytes_ReturnsTheSuppliedDek(t *testing.T) {
	dek := make([]byte, dekLength)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	expected := append([]byte(nil), dek...)

	key := newTestPipelineKey(t, dek)

	if !bytes.Equal(key.AsBytes(), expected) {
		t.Errorf("AsBytes() = %v, want %v", key.AsBytes(), expected)
	}
}

func TestPipelineDataEncryptionKey_EncryptDecrypt_RoundTrips(t *testing.T) {
	key := newTestPipelineKey(t, nil)
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
	if written != len(expected) || !bytes.Equal(decrypted, expected) {
		t.Errorf("decrypted = %q (%d bytes), want %q", decrypted, written, expected)
	}
}

func TestPipelineDataEncryptionKey_Decrypt_WithMismatchedAad_ReturnsError(t *testing.T) {
	key := newTestPipelineKey(t, nil)
	encrypted, err := key.Encrypt([]byte("top secret"), []byte("context-a"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	_, err = key.Decrypt(encrypted, []byte("context-b"), make([]byte, 16))
	if err == nil {
		t.Fatal("Decrypt() error = nil, want non-nil")
	}
}

func TestPipelineDataEncryptionKey_TwoInstances_WithDifferentDeks_CannotDecryptEachOthersCiphertext(t *testing.T) {
	key1 := newTestPipelineKey(t, nil)
	key2 := newTestPipelineKey(t, nil)

	encrypted, err := key1.Encrypt([]byte("top secret"), nil)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if _, err := key2.Decrypt(encrypted, nil, make([]byte, 16)); err == nil {
		t.Fatal("Decrypt() error = nil, want non-nil")
	}
}

func TestPipelineDataEncryptionKey_Close_ZeroesTheDek(t *testing.T) {
	dek := make([]byte, dekLength)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}

	key := newTestPipelineKey(t, dek)
	if err := key.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if !bytes.Equal(dek, make([]byte, dekLength)) {
		t.Errorf("dek = %v, want all-zero", dek)
	}
}

func TestPipelineDataEncryptionKey_Close_DoesNotError(t *testing.T) {
	// Regression coverage: AesGcmCryptoProvider's pipeline-only constructor leaves its
	// background-refresh fields nil, which must not crash Close once
	// PipelineDataEncryptionKey starts closing its provider.
	key := newTestPipelineKey(t, nil)

	if err := key.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
}
