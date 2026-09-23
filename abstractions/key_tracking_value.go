package abstractions

// KeyTrackingValue pairs a decrypted value with the KeyRing version whose key produced it.
type KeyTrackingValue struct {
	KeyVersion int
	Value      []byte
}
