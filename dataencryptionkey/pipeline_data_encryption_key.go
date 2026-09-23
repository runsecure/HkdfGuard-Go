package dataencryptionkey

import "github.com/runsecure/hkdfguard-go/abstractions"

// PipelineDataEncryptionKey is an abstractions.DataEncryptionKey backed by a plain 32-byte DEK,
// used directly - never wrapped, never unwrapped. Meant for a pipeline that needs to encrypt
// secrets in-flight before a durable KEK exists yet: build one via PipelineKeyFactory, encrypt
// whatever needs protecting during the pipeline, then read the same plaintext DEK back via
// AsBytes at the end of the chain to hand off to the platform's native "initialize" CLI utility,
// which independently wraps/registers it against a real KEK. Close zeroes the DEK.
type PipelineDataEncryptionKey struct {
	*EncryptionKeyBase

	provider abstractions.CryptoProvider
	dek      []byte
}

var _ abstractions.DataEncryptionKey = (*PipelineDataEncryptionKey)(nil)

func newPipelineDataEncryptionKey(provider abstractions.CryptoProvider, dek []byte) *PipelineDataEncryptionKey {
	return &PipelineDataEncryptionKey{
		EncryptionKeyBase: NewEncryptionKeyBase(provider),
		provider:          provider,
		dek:               dek,
	}
}

// AsBytes returns the plain, plaintext DEK this instance protects with - e.g. to hand off to the
// platform's native "initialize" CLI utility once the pipeline finishes. The returned slice
// aliases this instance's own copy - callers must not retain it past Close.
func (k *PipelineDataEncryptionKey) AsBytes() []byte {
	return k.dek
}

// Close closes the underlying provider, and zeroes the plaintext DEK.
func (k *PipelineDataEncryptionKey) Close() error {
	err := k.provider.Close()
	abstractions.ZeroMemory(k.dek)
	return err
}
