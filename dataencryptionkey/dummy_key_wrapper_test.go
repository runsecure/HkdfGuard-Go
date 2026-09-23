package dataencryptionkey

import "testing"

func TestDummyKeyWrapper_Encrypt_ReturnsZero(t *testing.T) {
	w := dummyKeyWrapper{}

	n, err := w.Encrypt(make([]byte, 32), make([]byte, 64))

	if err != nil {
		t.Fatalf("Encrypt() error = %v, want nil", err)
	}
	if n != 0 {
		t.Errorf("Encrypt() = %d, want 0", n)
	}
}

func TestDummyKeyWrapper_Decrypt_ReturnsZero(t *testing.T) {
	w := dummyKeyWrapper{}

	n, err := w.Decrypt(make([]byte, 32), make([]byte, 32))

	if err != nil {
		t.Fatalf("Decrypt() error = %v, want nil", err)
	}
	if n != 0 {
		t.Errorf("Decrypt() = %d, want 0", n)
	}
}

func TestDummyKeyWrapper_GenerateAndWrap_ReturnsZero(t *testing.T) {
	w := dummyKeyWrapper{}

	n, err := w.GenerateAndWrap(make([]byte, 32))

	if err != nil {
		t.Fatalf("GenerateAndWrap() error = %v, want nil", err)
	}
	if n != 0 {
		t.Errorf("GenerateAndWrap() = %d, want 0", n)
	}
}
