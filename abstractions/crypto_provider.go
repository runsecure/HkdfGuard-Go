package abstractions

import "io"

// CryptoProvider is a cached, key-bound AEAD encrypt/decrypt surface. Implementations own
// revealing and refreshing their own underlying key material internally - callers just call
// Encrypt/Decrypt on every operation and always get a currently-valid key, without ever seeing
// (or needing to manage) the session/expiry machinery behind it.
//
// Unlike the C#/Java originals, which overload Encrypt/Decrypt with and without an aad
// parameter, Go has no method overloading: Encrypt and Decrypt always take aad, and a caller
// with no additional authenticated data passes nil.
type CryptoProvider interface {
	io.Closer

	// Encrypt encrypts plaintext, writing the encrypted bytes into result and returning the
	// number of bytes written. aad may be nil.
	Encrypt(plaintext []byte, aad []byte, result []byte) (int, error)

	// Decrypt decrypts ciphertext, writing the decrypted bytes into result and returning the
	// number of bytes written. aad may be nil.
	Decrypt(ciphertext []byte, aad []byte, result []byte) (int, error)
}
