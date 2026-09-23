// Package keywrapping protects and reveals a DEK via the platform's native HkdfGuard KMS library
// (TPM2, Secure Enclave, or Platform Crypto Provider), bound through purego (no cgo required).
package keywrapping

// dekLength is the fixed length, in bytes, of every DEK this package wraps/unwraps/generates.
const dekLength = 32

// ok is the status code common to every platform's native library: the call succeeded.
const ok int32 = 0

// Error codes for libHkdfGuardKeyProtectionLinux.so.
const (
	linuxErrInvalidArgument     int32 = -1
	linuxErrBufferTooSmall      int32 = -2
	linuxErrProviderUnavailable int32 = -3
	linuxErrProviderError       int32 = -4
	linuxErrCryptoError         int32 = -5
	linuxErrInternalError       int32 = -6
	linuxErrInvalidUtf8         int32 = -7
	linuxErrMissingServiceName  int32 = -8
)

// Error codes for HkdfGuard.Kms.MacOS.v1.dylib. Each distinct service string gets its own,
// independent Secure Enclave key - wrapping under one service's identifier and unwrapping under
// a different one fails by design (macOSErrDecryptionFailed).
const (
	macOSErrInvalidInputLength       int32 = -1
	macOSErrOutputBufferTooSmall     int32 = -2
	macOSErrKeyUnavailable           int32 = -3
	macOSErrPublicKeyUnavailable     int32 = -4
	macOSErrEncryptionFailed         int32 = -5
	macOSErrDecryptionFailed         int32 = -6
	macOSErrUnexpectedOutputLength   int32 = -7
	macOSErrMissingServiceIdentifier int32 = -8
)

// Error codes for HkdfGuard.Kms.Windows.v1.dll.
const (
	windowsErrInvalidArg     int32 = -1
	windowsErrBufferTooSmall int32 = -2
	windowsErrProvider       int32 = -3
	windowsErrCrypto         int32 = -4
	windowsErrAuthFailed     int32 = -5
	windowsErrMalformed      int32 = -6
	windowsErrInternal       int32 = -7
)

// nativeCallResult is the result of a call into the native HkdfGuard KMS library: its status
// code (ok on success, or a negative, implementation-specific error code), and the number of
// bytes written to the destination buffer - or, on a buffer-too-small failure, the required
// capacity instead.
type nativeCallResult struct {
	status       int32
	bytesWritten int32
}

// kmsLibrary is the shared surface over a platform's native HkdfGuard KMS library. Every
// implementation wraps and unwraps a fixed-length DEK under a persistent, per-service KEK held
// outside the Go process (a TPM2 key, a Secure Enclave key, etc.) via that platform's
// hkdfguard_wrap_dek / hkdfguard_unwrap_dek / hkdfguard_generate_and_wrap_dek native functions -
// identical in shape across platforms, but each library's negative status codes mean different
// things, so callers must consult the concrete implementation they're using to interpret a
// non-ok result.
type kmsLibrary interface {
	// wrapDek wraps dek under the persistent KEK identified by service. service is a non-empty,
	// cross-platform identity of the KEK. dek must be exactly dekLength bytes. destination
	// receives the wrapped payload.
	wrapDek(service string, dek []byte, destination []byte) nativeCallResult

	// unwrapDek unwraps a payload previously produced by wrapDek for the same service,
	// recovering the original DEK into destination.
	unwrapDek(service string, wrapped []byte, destination []byte) nativeCallResult

	// generateAndWrapDek generates a fresh, cryptographically random DEK and immediately wraps
	// it under the persistent KEK identified by service into destination. The plaintext DEK
	// never crosses this boundary - recover it later via unwrapDek with the same service.
	generateAndWrapDek(service string, destination []byte) nativeCallResult
}
