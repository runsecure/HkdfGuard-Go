package dataencryptionkey

// fakeKeyWrapper always reveals the same fixed key - isolates these tests from any real native
// KMS machinery while still exercising real AES-GCM via a real cryptosession.AesGcmCryptoProvider.
type fakeKeyWrapper struct {
	key []byte
}

func newFakeKeyWrapper(key []byte) *fakeKeyWrapper {
	return &fakeKeyWrapper{key: key}
}

func (w *fakeKeyWrapper) Encrypt(plaintext []byte, result []byte) (int, error) {
	panic("fakeKeyWrapper only supports Decrypt")
}

func (w *fakeKeyWrapper) Decrypt(wrapped []byte, result []byte) (int, error) {
	return copy(result, w.key), nil
}

func (w *fakeKeyWrapper) GenerateAndWrap(result []byte) (int, error) {
	return copy(result, w.key), nil
}
