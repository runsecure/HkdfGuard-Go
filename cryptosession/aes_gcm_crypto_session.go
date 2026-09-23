// Package cryptosession is an AES-256-GCM AEAD cipher session bound to a KeyWrapper-revealed
// DEK, with a background provider that proactively refreshes and zeroes expired key material.
package cryptosession

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/runsecure/hkdfguard-go/abstractions"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"go.opentelemetry.io/otel/attribute"
)

const (
	nonceSize = 12
	tagSize   = 16
	keyLength = 32
)

// aesGcmCryptoSession holds one revealed 32-byte DEK's live AES-256-GCM cipher state. It is not
// part of this package's public API - AesGcmCryptoProvider owns the only instance in existence
// at any time, swapping it out for a fresh one on every background refresh (see
// AesGcmCryptoProvider.refresh); callers only ever see AesGcmCryptoProvider.Encrypt/Decrypt.
//
// Ciphertext produced by encrypt is laid out as nonce(12) || ciphertext || tag(16), matching the
// .NET/Java originals exactly, so wrapped payloads are byte-for-byte interchangeable across
// ports of this library.
type aesGcmCryptoSession struct {
	key  []byte
	aead cipher.AEAD
}

// newAesGcmCryptoSession builds a session around key, which must be exactly keyLength bytes and
// not all-zero. The session keeps its own copy of key (zeroed by close), so the caller remains
// free to zero or reuse its own copy immediately after this call returns.
func newAesGcmCryptoSession(key []byte) (*aesGcmCryptoSession, error) {
	if abstractions.IsNullOrEmpty(key) {
		return nil, errors.New("cryptosession: key must not be empty or all zero")
	}
	if len(key) != keyLength {
		return nil, fmt.Errorf("cryptosession: key must be exactly %d bytes, was %d", keyLength, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	stored := append([]byte(nil), key...)
	return &aesGcmCryptoSession{key: stored, aead: aead}, nil
}

// encrypt encrypts plaintext, writing nonce || ciphertext || tag into result and returning the
// number of bytes written. aad may be nil. plaintext is zeroed before returning, successful or
// not - callers must treat it as consumed.
func (s *aesGcmCryptoSession) encrypt(plaintext []byte, aad []byte, result []byte) (n int, err error) {
	tel := diagnostics.CryptoSessionAesGcm256
	_, span := tel.Tracer().Start(context.Background(), diagnostics.ActivityNames.CryptoSessionAesGcm256.Encrypt)
	defer span.End()
	defer abstractions.ZeroMemory(plaintext)
	defer func() {
		if err != nil {
			tel.RecordException(span, err)
		}
	}()

	tel.LogSensitiveOperation(span, diagnostics.ActivityNames.CryptoSessionAesGcm256.Encrypt,
		attribute.Int(diagnostics.AttributeNames.PlaintextLength, len(plaintext)),
		attribute.Int(diagnostics.AttributeNames.AadLength, len(aad)))

	if abstractions.IsNullOrEmpty(plaintext) {
		return 0, errors.New("cryptosession: plaintext must not be empty or all zero")
	}

	needed := nonceSize + len(plaintext) + tagSize
	if len(result) < needed {
		return 0, fmt.Errorf("cryptosession: result buffer too small: need %d bytes, have %d", needed, len(result))
	}

	nonce := result[:nonceSize]
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}

	sealed := s.aead.Seal(result[nonceSize:nonceSize], nonce, plaintext, aad)
	return nonceSize + len(sealed), nil
}

// decrypt reveals a payload previously produced by encrypt (nonce || ciphertext || tag),
// writing the plaintext into result and returning the number of bytes written. aad must match
// whatever was passed to encrypt.
func (s *aesGcmCryptoSession) decrypt(ciphertext []byte, aad []byte, result []byte) (n int, err error) {
	tel := diagnostics.CryptoSessionAesGcm256
	_, span := tel.Tracer().Start(context.Background(), diagnostics.ActivityNames.CryptoSessionAesGcm256.Decrypt)
	defer span.End()
	defer func() {
		if err != nil {
			tel.RecordException(span, err)
		}
	}()

	tel.LogSensitiveOperation(span, diagnostics.ActivityNames.CryptoSessionAesGcm256.Decrypt,
		attribute.Int(diagnostics.AttributeNames.CiphertextLength, len(ciphertext)),
		attribute.Int(diagnostics.AttributeNames.AadLength, len(aad)))

	if abstractions.IsNullOrEmpty(ciphertext) {
		return 0, errors.New("cryptosession: ciphertext must not be empty or all zero")
	}
	if len(ciphertext) < nonceSize+tagSize {
		return 0, fmt.Errorf("cryptosession: ciphertext too short: need at least %d bytes, have %d", nonceSize+tagSize, len(ciphertext))
	}

	resultLength := len(ciphertext) - nonceSize - tagSize
	if len(result) < resultLength {
		return 0, fmt.Errorf("cryptosession: result buffer too small: need %d bytes, have %d", resultLength, len(result))
	}

	nonce := ciphertext[:nonceSize]
	sealed := ciphertext[nonceSize:]

	opened, err := s.aead.Open(result[:0], nonce, sealed, aad)
	if err != nil {
		return 0, err
	}
	return len(opened), nil
}

// close zeroes this session's stored key copy. The underlying cipher.AEAD is left to the garbage
// collector - crypto/aes keeps no exported handle to release, unlike the native/OS-backed AEAD
// implementations the .NET/Java originals dispose explicitly.
func (s *aesGcmCryptoSession) close() {
	abstractions.ZeroMemory(s.key)
}
