package cryptosession

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, keyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	return key
}

func TestAesGcmCryptoSession_EncryptDecrypt_RoundTrips(t *testing.T) {
	session, err := newAesGcmCryptoSession(randomKey(t))
	if err != nil {
		t.Fatalf("newAesGcmCryptoSession() error = %v", err)
	}

	plaintext := []byte("hello world")
	expected := append([]byte(nil), plaintext...)
	encrypted := make([]byte, len(plaintext)+nonceSize+tagSize)

	written, err := session.encrypt(plaintext, nil, encrypted)
	if err != nil {
		t.Fatalf("encrypt() error = %v", err)
	}
	if written != len(encrypted) {
		t.Errorf("encrypt() = %d, want %d", written, len(encrypted))
	}

	decrypted := make([]byte, len(expected))
	decryptedLen, err := session.decrypt(encrypted, nil, decrypted)
	if err != nil {
		t.Fatalf("decrypt() error = %v", err)
	}
	if decryptedLen != len(expected) {
		t.Errorf("decrypt() = %d, want %d", decryptedLen, len(expected))
	}
	if !bytes.Equal(decrypted, expected) {
		t.Errorf("decrypted = %v, want %v", decrypted, expected)
	}
}

func TestAesGcmCryptoSession_EncryptDecrypt_RoundTrips_WithAad(t *testing.T) {
	session, err := newAesGcmCryptoSession(randomKey(t))
	if err != nil {
		t.Fatalf("newAesGcmCryptoSession() error = %v", err)
	}

	plaintext := []byte("hello world")
	expected := append([]byte(nil), plaintext...)
	aad := []byte("context")
	encrypted := make([]byte, len(plaintext)+nonceSize+tagSize)

	if _, err := session.encrypt(plaintext, aad, encrypted); err != nil {
		t.Fatalf("encrypt() error = %v", err)
	}

	decrypted := make([]byte, len(expected))
	if _, err := session.decrypt(encrypted, aad, decrypted); err != nil {
		t.Fatalf("decrypt() error = %v", err)
	}
	if !bytes.Equal(decrypted, expected) {
		t.Errorf("decrypted = %v, want %v", decrypted, expected)
	}
}

func TestAesGcmCryptoSession_Decrypt_WithWrongAad_Errors(t *testing.T) {
	session, err := newAesGcmCryptoSession(randomKey(t))
	if err != nil {
		t.Fatalf("newAesGcmCryptoSession() error = %v", err)
	}

	plaintext := []byte("hello world")
	encrypted := make([]byte, len(plaintext)+nonceSize+tagSize)
	if _, err := session.encrypt(plaintext, []byte("correct-aad"), encrypted); err != nil {
		t.Fatalf("encrypt() error = %v", err)
	}

	decrypted := make([]byte, len(plaintext))
	if _, err := session.decrypt(encrypted, []byte("wrong-aad"), decrypted); err == nil {
		t.Fatal("decrypt() error = nil, want error")
	}
}

func TestAesGcmCryptoSession_Decrypt_WithTamperedCiphertext_Errors(t *testing.T) {
	session, err := newAesGcmCryptoSession(randomKey(t))
	if err != nil {
		t.Fatalf("newAesGcmCryptoSession() error = %v", err)
	}

	plaintext := []byte("hello world")
	encrypted := make([]byte, len(plaintext)+nonceSize+tagSize)
	if _, err := session.encrypt(plaintext, nil, encrypted); err != nil {
		t.Fatalf("encrypt() error = %v", err)
	}
	encrypted[15] ^= 0xFF

	decrypted := make([]byte, len(plaintext))
	if _, err := session.decrypt(encrypted, nil, decrypted); err == nil {
		t.Fatal("decrypt() error = nil, want error")
	}
}

func TestAesGcmCryptoSession_Encrypt_WithTooSmallResultBuffer_Errors(t *testing.T) {
	session, err := newAesGcmCryptoSession(randomKey(t))
	if err != nil {
		t.Fatalf("newAesGcmCryptoSession() error = %v", err)
	}

	plaintext := []byte("hello world")
	tooSmall := make([]byte, len(plaintext))

	if _, err := session.encrypt(plaintext, nil, tooSmall); err == nil {
		t.Fatal("encrypt() error = nil, want error")
	}
}

func TestAesGcmCryptoSession_Decrypt_WithTooShortCiphertext_Errors(t *testing.T) {
	session, err := newAesGcmCryptoSession(randomKey(t))
	if err != nil {
		t.Fatalf("newAesGcmCryptoSession() error = %v", err)
	}

	tooShort := make([]byte, 10)
	result := make([]byte, 4)

	if _, err := session.decrypt(tooShort, nil, result); err == nil {
		t.Fatal("decrypt() error = nil, want error")
	}
}

func TestAesGcmCryptoSession_Decrypt_WithNonZeroButTooShortCiphertext_Errors(t *testing.T) {
	session, err := newAesGcmCryptoSession(randomKey(t))
	if err != nil {
		t.Fatalf("newAesGcmCryptoSession() error = %v", err)
	}

	tooShort := randomKey(t)[:10] // non-zero, but shorter than nonce + tag
	result := make([]byte, 4)

	if _, err := session.decrypt(tooShort, nil, result); err == nil {
		t.Fatal("decrypt() error = nil, want error")
	}
}

func TestAesGcmCryptoSession_Decrypt_WithTooSmallResultBuffer_Errors(t *testing.T) {
	session, err := newAesGcmCryptoSession(randomKey(t))
	if err != nil {
		t.Fatalf("newAesGcmCryptoSession() error = %v", err)
	}

	plaintext := []byte("hello world")
	encrypted := make([]byte, len(plaintext)+nonceSize+tagSize)
	if _, err := session.encrypt(plaintext, nil, encrypted); err != nil {
		t.Fatalf("encrypt() error = %v", err)
	}

	tooSmall := make([]byte, len(plaintext)-1)
	if _, err := session.decrypt(encrypted, nil, tooSmall); err == nil {
		t.Fatal("decrypt() error = nil, want error")
	}
}

func TestNewAesGcmCryptoSession_WithInvalidKeySize_Errors(t *testing.T) {
	invalidKey := make([]byte, 10)
	if _, err := rand.Read(invalidKey); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}

	if _, err := newAesGcmCryptoSession(invalidKey); err == nil {
		t.Fatal("newAesGcmCryptoSession() error = nil, want error")
	}
}

func TestNewAesGcmCryptoSession_WithAllZeroKey_Errors(t *testing.T) {
	zeroKey := make([]byte, keyLength)
	if _, err := newAesGcmCryptoSession(zeroKey); err == nil {
		t.Fatal("newAesGcmCryptoSession() error = nil, want error")
	}
}

func TestAesGcmCryptoSession_Encrypt_WithAllZeroPlaintext_Errors(t *testing.T) {
	session, err := newAesGcmCryptoSession(randomKey(t))
	if err != nil {
		t.Fatalf("newAesGcmCryptoSession() error = %v", err)
	}

	zeroPlaintext := make([]byte, 11)
	encrypted := make([]byte, len(zeroPlaintext)+nonceSize+tagSize)

	if _, err := session.encrypt(zeroPlaintext, nil, encrypted); err == nil {
		t.Fatal("encrypt() error = nil, want error")
	}
}

func TestAesGcmCryptoSession_Close_ZeroesTheKey(t *testing.T) {
	key := randomKey(t)
	keyClone := append([]byte(nil), key...)
	session, err := newAesGcmCryptoSession(key)
	if err != nil {
		t.Fatalf("newAesGcmCryptoSession() error = %v", err)
	}

	session.close()

	if !bytes.Equal(session.key, make([]byte, keyLength)) {
		t.Error("session.key was not zeroed after close()")
	}
	if bytes.Equal(session.key, keyClone) {
		t.Error("session.key still equals the original key after close()")
	}
}
