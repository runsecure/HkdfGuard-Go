package abstractions

// DataProtector is a named, string-level data protector: the name given at construction is used
// as the additional authenticated data for every Encrypt/Decrypt, binding a protected value to
// the purpose it was protected for so it can't be reused under a different one. Encrypt/Decrypt
// resolve the actual DataProtectionKey to use from a KeyRing, rather than holding one key
// permanently.
type DataProtector interface {
	// Encrypt encrypts plaintext and formats the result via the configured
	// EncryptedFormatProvider.
	Encrypt(plaintext string) (string, error)

	// Decrypt parses a formatted encrypted string via the configured EncryptedFormatProvider and
	// decrypts it directly into result - this never materializes the plaintext as a string.
	// Returns the number of bytes written to result.
	Decrypt(encrypted string, result []byte) (int, error)

	// GetMaxDecryptedLength computes an upper bound on how many bytes Decrypt will write for the
	// given formatted string, so a result buffer can be sized without decrypting first.
	GetMaxDecryptedLength(encrypted string) (int, error)
}
