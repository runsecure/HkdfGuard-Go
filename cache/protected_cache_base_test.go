package cache

import (
	"bytes"
	"testing"
)

// fakeDataEncryptionKey is a no-op "encryption" stand-in: Encrypt/Decrypt just copy bytes
// through unchanged, so tests can assert on plaintext round-tripping without a real cipher.
type fakeDataEncryptionKey struct {
	encryptFn func(plaintext []byte, aad []byte) ([]byte, error)
}

func (f *fakeDataEncryptionKey) Encrypt(plaintext []byte, aad []byte) ([]byte, error) {
	if f.encryptFn != nil {
		return f.encryptFn(plaintext, aad)
	}
	return append([]byte(nil), plaintext...), nil
}

func (f *fakeDataEncryptionKey) Decrypt(ciphertext []byte, aad []byte, result []byte) (int, error) {
	return copy(result, ciphertext), nil
}

func TestProtectedCacheBase_Decrypt_MissingName_ReturnsZero(t *testing.T) {
	sut := NewProtectedCacheBase(&fakeDataEncryptionKey{})

	written, err := sut.Decrypt("missing", make([]byte, 16))

	if err != nil {
		t.Fatalf("Decrypt() error = %v, want nil", err)
	}
	if written != 0 {
		t.Errorf("Decrypt() = %d, want 0", written)
	}
}

func TestProtectedCacheBase_Decrypt_PresentName_IsCaseInsensitive(t *testing.T) {
	sut := NewProtectedCacheBase(&fakeDataEncryptionKey{})
	encrypted := []byte{1, 2, 3}
	sut.SetEncrypted("MyName", encrypted)

	result := make([]byte, 3)
	written, err := sut.Decrypt("myname", result)

	if err != nil {
		t.Fatalf("Decrypt() error = %v, want nil", err)
	}
	if written != 3 {
		t.Errorf("Decrypt() = %d, want 3", written)
	}
	if !bytes.Equal(result, encrypted) {
		t.Errorf("result = %v, want %v", result, encrypted)
	}
}

func TestProtectedCacheBase_Decrypt_RoundTripsMultiByteUtf8Text(t *testing.T) {
	sut := NewProtectedCacheBase(&fakeDataEncryptionKey{})
	plaintext := "héllo wörld éèê"
	sut.SetEncrypted("greeting", []byte(plaintext))

	result := make([]byte, len(plaintext))
	written, err := sut.Decrypt("greeting", result)

	if err != nil {
		t.Fatalf("Decrypt() error = %v, want nil", err)
	}
	if string(result[:written]) != plaintext {
		t.Errorf("Decrypt() = %q, want %q", string(result[:written]), plaintext)
	}
}

func TestProtectedCacheBase_TryGetMaxDecryptedLength_MissingName_ReturnsFalse(t *testing.T) {
	sut := NewProtectedCacheBase(&fakeDataEncryptionKey{})

	_, found := sut.TryGetMaxDecryptedLength("missing")

	if found {
		t.Errorf("TryGetMaxDecryptedLength() found = true, want false")
	}
}

func TestProtectedCacheBase_TryGetMaxDecryptedLength_PresentName_ReturnsEncryptedLength(t *testing.T) {
	sut := NewProtectedCacheBase(&fakeDataEncryptionKey{})
	sut.SetEncrypted("name", []byte{1, 2, 3, 4, 5})

	length, found := sut.TryGetMaxDecryptedLength("name")

	if !found {
		t.Fatalf("TryGetMaxDecryptedLength() found = false, want true")
	}
	if length != 5 {
		t.Errorf("TryGetMaxDecryptedLength() = %d, want 5", length)
	}
}

func TestProtectedCacheBase_TryPopulate_NilByDefault_DecryptReturnsZero(t *testing.T) {
	sut := NewProtectedCacheBase(&fakeDataEncryptionKey{})

	written, _ := sut.Decrypt("anything", make([]byte, 16))

	if written != 0 {
		t.Errorf("Decrypt() = %d, want 0", written)
	}
}

func TestProtectedCacheBase_TryPopulate_CalledOnMiss_PopulatesAndSucceeds(t *testing.T) {
	sut := NewProtectedCacheBase(&fakeDataEncryptionKey{})
	calls := 0
	sut.TryPopulate = func(name string) bool {
		calls++
		sut.SetEncrypted(name, []byte{9, 9, 9})
		return true
	}

	result := make([]byte, 3)
	written, err := sut.Decrypt("fetched", result)

	if err != nil {
		t.Fatalf("Decrypt() error = %v, want nil", err)
	}
	if calls != 1 {
		t.Errorf("TryPopulate calls = %d, want 1", calls)
	}
	if written != 3 || !bytes.Equal(result, []byte{9, 9, 9}) {
		t.Errorf("Decrypt() = (%d, %v), want (3, [9 9 9])", written, result)
	}

	// A second Decrypt of the same name must not call TryPopulate again - the value is now cached.
	_, _ = sut.Decrypt("fetched", result)
	if calls != 1 {
		t.Errorf("TryPopulate calls after second Decrypt = %d, want 1", calls)
	}
}

func TestProtectedCacheBase_Encrypt_DelegatesToDataEncryptionKeyWithNilAad(t *testing.T) {
	var gotAad []byte
	sut := NewProtectedCacheBase(&fakeDataEncryptionKey{
		encryptFn: func(plaintext []byte, aad []byte) ([]byte, error) {
			gotAad = aad
			return []byte{9, 9, 9}, nil
		},
	})

	encrypted, err := sut.Encrypt([]byte("secret"))

	if err != nil {
		t.Fatalf("Encrypt() error = %v, want nil", err)
	}
	if !bytes.Equal(encrypted, []byte{9, 9, 9}) {
		t.Errorf("Encrypt() = %v, want [9 9 9]", encrypted)
	}
	if gotAad != nil {
		t.Errorf("aad = %v, want nil", gotAad)
	}
}

func TestProtectedCacheBase_TryAddEncrypted_RejectsDuplicateName(t *testing.T) {
	sut := NewProtectedCacheBase(&fakeDataEncryptionKey{})

	first := sut.TryAddEncrypted("name", []byte{1})
	second := sut.TryAddEncrypted("NAME", []byte{2})

	if !first {
		t.Errorf("first TryAddEncrypted() = false, want true")
	}
	if second {
		t.Errorf("second TryAddEncrypted() = true, want false")
	}
}
