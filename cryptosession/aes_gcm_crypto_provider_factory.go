package cryptosession

import "github.com/runsecure/hkdfguard-go/abstractions"

// AesGcmCryptoProviderFactory builds AesGcmCryptoProvider instances, implementing
// abstractions.CryptoProviderFactory.
type AesGcmCryptoProviderFactory struct{}

var _ abstractions.CryptoProviderFactory = AesGcmCryptoProviderFactory{}

// Create builds a provider that reveals wrapped through wrapper, refreshing every
// expirySeconds.
func (AesGcmCryptoProviderFactory) Create(wrapper abstractions.KeyWrapper, wrapped []byte, expirySeconds int) (abstractions.CryptoProvider, error) {
	return NewAesGcmCryptoProvider(wrapper, wrapped, expirySeconds)
}

// CreateEphemeral generates a fresh DEK via wrapper.GenerateAndWrap and builds a provider around
// it, refreshing every expirySeconds.
func (AesGcmCryptoProviderFactory) CreateEphemeral(wrapper abstractions.KeyWrapper, expirySeconds int) (abstractions.CryptoProvider, error) {
	wrapped := make([]byte, 512)
	n, err := wrapper.GenerateAndWrap(wrapped)
	if err != nil {
		return nil, err
	}

	return NewAesGcmCryptoProvider(wrapper, wrapped[:n], expirySeconds)
}

// CreateForPipeline builds a provider around notWrapped directly - notWrapped is already a
// plaintext DEK, never wrapped or unwrapped through wrapper.
func (AesGcmCryptoProviderFactory) CreateForPipeline(wrapper abstractions.KeyWrapper, notWrapped []byte) (abstractions.CryptoProvider, error) {
	return newAesGcmCryptoProviderForPipeline(wrapper, notWrapped)
}
