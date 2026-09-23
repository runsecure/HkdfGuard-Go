package keywrapping

import "github.com/runsecure/hkdfguard-go/abstractions"

// NativeHkdfKeyWrapperV1 protects (Encrypt) a fresh DEK, or reveals (Decrypt) a previously-
// wrapped one, via the current OS's native HkdfGuard KMS library (see getLibrary) - a TPM2,
// Secure Enclave, or Platform Crypto Provider key held entirely outside this process, identified
// only by a service name. No salt/blob machinery is involved: the native library owns the KEK,
// the wrapped payload's format, and its own key derivation. Since Decrypt takes its wrapped
// payload as an explicit argument rather than one bound at construction, a single instance
// freely handles both directions, and any number of different wrapped payloads sharing the same
// service name. The native ABI has no concept of AAD, so KeyWrapper itself does not expose an
// AAD-taking method.
type NativeHkdfKeyWrapperV1 struct {
	serviceName string
	library     kmsLibrary
}

var _ abstractions.KeyWrapper = (*NativeHkdfKeyWrapperV1)(nil)

// NewNativeHkdfKeyWrapperV1 builds a wrapper bound to serviceName, using the current OS's native
// HkdfGuard KMS library (resolved once per process - see getLibrary).
func NewNativeHkdfKeyWrapperV1(serviceName string) (*NativeHkdfKeyWrapperV1, error) {
	library, err := getLibrary()
	if err != nil {
		return nil, err
	}
	return newNativeHkdfKeyWrapperV1(serviceName, library), nil
}

func newNativeHkdfKeyWrapperV1(serviceName string, library kmsLibrary) *NativeHkdfKeyWrapperV1 {
	return &NativeHkdfKeyWrapperV1{serviceName: serviceName, library: library}
}

// Encrypt wraps plaintext under the KEK identified by this wrapper's service name.
func (w *NativeHkdfKeyWrapperV1) Encrypt(plaintext []byte, result []byte) (int, error) {
	r := w.library.wrapDek(w.serviceName, plaintext, result)
	if r.status != ok {
		return 0, newNativeKmsError("native KMS wrap failed with status %d", r.status)
	}
	return int(r.bytesWritten), nil
}

// Decrypt reveals a payload previously produced by Encrypt for the same service name.
func (w *NativeHkdfKeyWrapperV1) Decrypt(wrapped []byte, result []byte) (int, error) {
	r := w.library.unwrapDek(w.serviceName, wrapped, result)
	if r.status != ok {
		return 0, newNativeKmsError("native KMS unwrap failed with status %d", r.status)
	}
	return int(r.bytesWritten), nil
}

// GenerateAndWrap generates a fresh DEK and immediately wraps it under this wrapper's service
// name - the plaintext DEK never crosses this call's return value.
func (w *NativeHkdfKeyWrapperV1) GenerateAndWrap(result []byte) (int, error) {
	r := w.library.generateAndWrapDek(w.serviceName, result)
	if r.status != ok {
		return 0, newNativeKmsError("native KMS generate-and-wrap failed with status %d", r.status)
	}
	return int(r.bytesWritten), nil
}
