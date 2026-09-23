package dataencryptionkey

import (
	"crypto/rand"

	"github.com/runsecure/hkdfguard-go/abstractions"
)

const dekLength = 32

// PipelineKeyFactory builds fresh PipelineDataEncryptionKey instances, each around a newly
// generated random 32-byte DEK.
//
// The C#/Java originals' Create also accepts a format-provider argument and an optional key
// version, neither of which its own implementation ever reads (a pipeline key isn't registered
// in a KeyRing, so it has no format or version to speak of) - Go's Create drops both rather than
// carrying two parameters that do nothing.
type PipelineKeyFactory struct{}

// Create generates a fresh, cryptographically random 32-byte DEK and builds a
// PipelineDataEncryptionKey around it via factory.CreateForPipeline.
func (PipelineKeyFactory) Create(factory abstractions.CryptoProviderFactory) (*PipelineDataEncryptionKey, error) {
	dek := make([]byte, dekLength)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}

	provider, err := factory.CreateForPipeline(dummyKeyWrapper{}, dek)
	if err != nil {
		return nil, err
	}

	return newPipelineDataEncryptionKey(provider, dek), nil
}
