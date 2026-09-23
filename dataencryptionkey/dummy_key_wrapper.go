package dataencryptionkey

import "github.com/runsecure/hkdfguard-go/abstractions"

// dummyKeyWrapper stands in for the abstractions.KeyWrapper the pipeline flow's
// CryptoProviderFactory.CreateForPipeline requires but never actually calls (the DEK is used
// as-is, never wrapped) - every member is an inert no-op.
type dummyKeyWrapper struct{}

var _ abstractions.KeyWrapper = dummyKeyWrapper{}

func (dummyKeyWrapper) Encrypt(plaintext []byte, result []byte) (int, error) {
	return 0, nil
}

func (dummyKeyWrapper) Decrypt(wrapped []byte, result []byte) (int, error) {
	return 0, nil
}

func (dummyKeyWrapper) GenerateAndWrap(result []byte) (int, error) {
	return 0, nil
}
