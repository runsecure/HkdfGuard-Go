package abstractions

// DataProtectionKey wraps (protects) and unwraps (reveals) an encryption key.
//
// Unlike the C#/Java originals, which overload Encrypt/Decrypt with and without an aad
// parameter, Go has no method overloading: Encrypt and Decrypt always take aad, and a caller
// with no additional authenticated data passes nil.
type DataProtectionKey interface {
	// Encrypt protects plaintext, returning the encrypted key ready to be stored. aad may be
	// nil.
	Encrypt(plaintext []byte, aad []byte) ([]byte, error)

	// Decrypt reveals ciphertext, writing the decrypted key into result and returning the
	// number of bytes written. aad may be nil.
	Decrypt(ciphertext []byte, aad []byte, result []byte) (int, error)
}
