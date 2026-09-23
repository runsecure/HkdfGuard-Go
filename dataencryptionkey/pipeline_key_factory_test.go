package dataencryptionkey

import (
	"bytes"
	"testing"
)

func TestPipelineKeyFactory_Create_GeneratesA32ByteDek(t *testing.T) {
	factory := PipelineKeyFactory{}

	key, err := factory.Create(cryptoProviderFactory)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() { _ = key.Close() })

	if len(key.AsBytes()) != 32 {
		t.Errorf("len(AsBytes()) = %d, want 32", len(key.AsBytes()))
	}
	if bytes.Equal(key.AsBytes(), make([]byte, 32)) {
		t.Error("AsBytes() is all-zero, want random")
	}
}

func TestPipelineKeyFactory_Create_GeneratesADifferentDekEachTime(t *testing.T) {
	factory := PipelineKeyFactory{}

	key1, err := factory.Create(cryptoProviderFactory)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() { _ = key1.Close() })

	key2, err := factory.Create(cryptoProviderFactory)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() { _ = key2.Close() })

	if bytes.Equal(key1.AsBytes(), key2.AsBytes()) {
		t.Error("two Create() calls produced the same DEK")
	}
}

func TestPipelineKeyFactory_Create_ProducesAWorkingKey(t *testing.T) {
	factory := PipelineKeyFactory{}

	key, err := factory.Create(cryptoProviderFactory)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() { _ = key.Close() })

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

func TestPipelineKeyFactory_Create_KeyCanBeClosedWithoutError(t *testing.T) {
	factory := PipelineKeyFactory{}

	key, err := factory.Create(cryptoProviderFactory)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := key.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}
