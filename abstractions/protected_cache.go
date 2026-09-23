package abstractions

// ProtectedCache is the read/write surface of a highly concurrent name -> encrypted-value cache
// backed by a single DataProtectionKey. Add/AddOrUpdate protect and store plaintext under a
// name; the read surface (Decrypt/TryGetMaxDecryptedLength) is inherited from
// ProtectedReadOnlyCache. Nothing here ever holds plaintext beyond the duration of a single
// Add/AddOrUpdate call - only the encrypted bytes are retained internally.
//
// Unlike the C#/Java originals, which overload Add/AddOrUpdate for raw bytes and for text, Go
// represents both identically as []byte (a Go string already is UTF-8 bytes, so storing text is
// just Add(name, []byte(text)) - no separate overload or transcoding step is needed).
type ProtectedCache interface {
	ProtectedReadOnlyCache

	// Add encrypts plaintext and stores it under name. plaintext is zeroed as a side effect of
	// encrypting it. Returns an error if a value is already stored under name.
	Add(name string, plaintext []byte) error

	// AddOrUpdate encrypts plaintext and stores it under name, replacing any value already
	// stored under that name. plaintext is zeroed as a side effect of encrypting it.
	AddOrUpdate(name string, plaintext []byte) error
}
