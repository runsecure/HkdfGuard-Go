// Package abstractions holds shared interfaces for HkdfGuard's Go components.
package abstractions

// KeyWrapper protects (Encrypt) and reveals (Decrypt) an encryption key against a single,
// implicitly identified KEK (e.g. a native KMS-backed key, identified by service name at
// construction). Decrypt takes the wrapped payload as an explicit argument on every call, so one
// implementation can reveal any number of different wrapped keys sharing the same KEK - it holds
// no wrapped payload of its own.
type KeyWrapper interface {
	// Encrypt protects an encryption key, writing the encrypted bytes into result and returning
	// the number of bytes written.
	Encrypt(plaintext []byte, result []byte) (int, error)

	// Decrypt reveals a previously-wrapped key, writing the decrypted bytes into result and
	// returning the number of bytes written.
	Decrypt(wrapped []byte, result []byte) (int, error)

	// GenerateAndWrap generates a fresh key and immediately protects it against the same KEK
	// this implementation wraps/reveals against - the plaintext key never crosses this call's
	// return value. Writes the wrapped bytes into result and returns the number of bytes
	// written.
	GenerateAndWrap(result []byte) (int, error)
}
