package dataencryptionkey

import (
	"bytes"
	"testing"
)

func TestKeyRing_CurrentVersion_BeforeAnyAdd_ReturnsError(t *testing.T) {
	ring := NewKeyRing(DefaultFormatProvider{})

	if _, err := ring.CurrentVersion(); err == nil {
		t.Error("CurrentVersion() error = nil, want non-nil")
	}
}

func TestKeyRing_Add_HighestVersionBecomesCurrent(t *testing.T) {
	ring := NewKeyRing(DefaultFormatProvider{})
	key1 := newTestKey(t)
	key2 := newTestKey(t)

	if err := ring.Add(1, key1); err != nil {
		t.Fatalf("Add(1) error = %v", err)
	}
	if err := ring.Add(2, key2); err != nil {
		t.Fatalf("Add(2) error = %v", err)
	}

	version, err := ring.CurrentVersion()
	if err != nil {
		t.Fatalf("CurrentVersion() error = %v", err)
	}
	if version != 2 {
		t.Errorf("CurrentVersion() = %d, want 2", version)
	}
}

func TestKeyRing_Add_LowerVersionAfterHigher_DoesNotBecomeCurrent(t *testing.T) {
	ring := NewKeyRing(DefaultFormatProvider{})
	if err := ring.Add(2, newTestKey(t)); err != nil {
		t.Fatalf("Add(2) error = %v", err)
	}
	if err := ring.Add(1, newTestKey(t)); err != nil {
		t.Fatalf("Add(1) error = %v", err)
	}

	version, err := ring.CurrentVersion()
	if err != nil {
		t.Fatalf("CurrentVersion() error = %v", err)
	}
	if version != 2 {
		t.Errorf("CurrentVersion() = %d, want 2", version)
	}
}

func TestKeyRing_Add_DuplicateVersion_ReturnsError(t *testing.T) {
	ring := NewKeyRing(DefaultFormatProvider{})
	if err := ring.Add(1, newTestKey(t)); err != nil {
		t.Fatalf("Add(1) error = %v", err)
	}

	if err := ring.Add(1, newTestKey(t)); err == nil {
		t.Error("second Add(1) error = nil, want non-nil")
	}
}

func TestKeyRing_Get_MissingVersion_ReturnsError(t *testing.T) {
	ring := NewKeyRing(DefaultFormatProvider{})

	if _, err := ring.Get(1); err == nil {
		t.Error("Get(1) error = nil, want non-nil")
	}
}

func TestKeyRing_TryGet_MissingVersion_ReturnsFalse(t *testing.T) {
	ring := NewKeyRing(DefaultFormatProvider{})

	if _, found := ring.TryGet(1); found {
		t.Error("TryGet(1) found = true, want false")
	}
}

func TestKeyRing_TryGet_PresentVersion_ReturnsTrue(t *testing.T) {
	ring := NewKeyRing(DefaultFormatProvider{})
	key := newTestKey(t)
	if err := ring.Add(1, key); err != nil {
		t.Fatalf("Add(1) error = %v", err)
	}

	got, found := ring.TryGet(1)
	if !found {
		t.Fatal("TryGet(1) found = false, want true")
	}
	if got != key {
		t.Error("TryGet(1) returned a different key than was added")
	}
}

func TestKeyRing_GetCurrent_ReturnsHighestVersionAndItsKey(t *testing.T) {
	ring := NewKeyRing(DefaultFormatProvider{})
	key1 := newTestKey(t)
	key2 := newTestKey(t)
	if err := ring.Add(1, key1); err != nil {
		t.Fatalf("Add(1) error = %v", err)
	}
	if err := ring.Add(2, key2); err != nil {
		t.Fatalf("Add(2) error = %v", err)
	}

	version, key, err := ring.GetCurrent()
	if err != nil {
		t.Fatalf("GetCurrent() error = %v", err)
	}
	if version != 2 {
		t.Errorf("version = %d, want 2", version)
	}
	if key != key2 {
		t.Error("GetCurrent() returned a different key than version 2's")
	}
}

func TestKeyRing_CreateProtector_EncryptDecrypt_RoundTrips(t *testing.T) {
	ring := NewKeyRing(DefaultFormatProvider{})
	if err := ring.Add(1, newTestKey(t)); err != nil {
		t.Fatalf("Add(1) error = %v", err)
	}

	protector := ring.CreateProtector("purpose")
	encrypted, err := protector.Encrypt("hello world")
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	result := make([]byte, 32)
	written, err := protector.Decrypt(encrypted, result)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(result[:written], []byte("hello world")) {
		t.Errorf("Decrypt() = %q, want %q", result[:written], "hello world")
	}
}

func TestKeyRing_CreateProtector_DifferentName_CannotDecryptEachOthers(t *testing.T) {
	ring := NewKeyRing(DefaultFormatProvider{})
	if err := ring.Add(1, newTestKey(t)); err != nil {
		t.Fatalf("Add(1) error = %v", err)
	}

	encrypted, err := ring.CreateProtector("purpose-a").Encrypt("hello world")
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if _, err := ring.CreateProtector("purpose-b").Decrypt(encrypted, make([]byte, 32)); err == nil {
		t.Error("Decrypt() error = nil, want non-nil")
	}
}
