package abstractions

// EncryptedFormatProvider formats a KeyTrackingValue as a string for storage, and parses it back.
type EncryptedFormatProvider interface {
	// Format renders value as a string.
	Format(value KeyTrackingValue) string

	// Parse parses a string previously produced by Format.
	Parse(encrypted string) (KeyTrackingValue, error)

	// GetMaxDecryptedLength computes an upper bound on the decrypted plaintext's length from the
	// encrypted payload's length alone, without decoding it. AEAD ciphertext is always at least
	// as long as the plaintext it encloses, so the actual decrypted length is this value or
	// less - always safe to size a result buffer to what this returns.
	GetMaxDecryptedLength(encrypted string) (int, error)
}
