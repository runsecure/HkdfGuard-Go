package cache

import "testing"

func TestProtectedCacheCollection_Decrypt_ChecksSourcesInOrder(t *testing.T) {
	first := NewProtectedCache(newTestDataEncryptionKey(t), nil)
	second := NewProtectedCache(newTestDataEncryptionKey(t), nil)
	if err := second.Add("name", []byte("from-second")); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	collection := NewProtectedCacheCollection().Add(first).Add(second)

	result := make([]byte, len("from-second"))
	written, err := collection.Decrypt("name", result)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if string(result[:written]) != "from-second" {
		t.Errorf("Decrypt() = %q, want %q", result[:written], "from-second")
	}
}

func TestProtectedCacheCollection_Decrypt_ReturnsFirstMatch(t *testing.T) {
	first := NewProtectedCache(newTestDataEncryptionKey(t), nil)
	second := NewProtectedCache(newTestDataEncryptionKey(t), nil)
	if err := first.Add("name", []byte("from-first")); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err := second.Add("name", []byte("from-second")); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	collection := NewProtectedCacheCollection().Add(first).Add(second)

	result := make([]byte, len("from-first"))
	written, err := collection.Decrypt("name", result)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if string(result[:written]) != "from-first" {
		t.Errorf("Decrypt() = %q, want %q", result[:written], "from-first")
	}
}

func TestProtectedCacheCollection_Decrypt_NoSourceHasName_ReturnsZero(t *testing.T) {
	collection := NewProtectedCacheCollection().
		Add(NewProtectedCache(newTestDataEncryptionKey(t), nil)).
		Add(NewProtectedCache(newTestDataEncryptionKey(t), nil))

	written, err := collection.Decrypt("missing", make([]byte, 16))
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if written != 0 {
		t.Errorf("Decrypt() = %d, want 0", written)
	}
}

func TestProtectedCacheCollection_TryGetMaxDecryptedLength_ChecksSourcesInOrder(t *testing.T) {
	first := NewProtectedCache(newTestDataEncryptionKey(t), nil)
	second := NewProtectedCache(newTestDataEncryptionKey(t), nil)
	if err := second.Add("name", []byte("from-second")); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	collection := NewProtectedCacheCollection().Add(first).Add(second)

	maxLength, found := collection.TryGetMaxDecryptedLength("name")
	if !found {
		t.Fatal("TryGetMaxDecryptedLength() found = false, want true")
	}
	if maxLength < len("from-second") {
		t.Errorf("TryGetMaxDecryptedLength() = %d, want >= %d", maxLength, len("from-second"))
	}
}

func TestProtectedCacheCollection_TryGetMaxDecryptedLength_NoSourceHasName_ReturnsFalse(t *testing.T) {
	collection := NewProtectedCacheCollection().Add(NewProtectedCache(newTestDataEncryptionKey(t), nil))

	if _, found := collection.TryGetMaxDecryptedLength("missing"); found {
		t.Error("TryGetMaxDecryptedLength() found = true, want false")
	}
}
