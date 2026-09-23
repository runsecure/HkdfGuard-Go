package abstractions

// ProtectedReadOnlyCache is the read surface of a highly concurrent name -> encrypted-value
// cache backed by a single DataEncryptionKey. Names are compared case-insensitively. Decrypt
// reveals a stored value back into a caller-owned buffer, returning (0, nil) for a missing name
// rather than an error. Nothing here ever holds plaintext beyond the duration of a single
// Decrypt call - only the encrypted bytes are retained internally.
type ProtectedReadOnlyCache interface {
	// Decrypt decrypts the value stored under name into result, returning the number of bytes
	// written, or (0, nil) if no value is stored under name.
	Decrypt(name string, result []byte) (int, error)

	// TryGetMaxDecryptedLength computes an upper bound on how many bytes Decrypt will write for
	// the value stored under name, so a result buffer can be sized without decrypting first. The
	// bool result reports whether a value is stored under name.
	TryGetMaxDecryptedLength(name string) (int, bool)
}
