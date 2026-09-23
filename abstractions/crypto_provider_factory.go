package abstractions

// CryptoProviderFactory builds CryptoProvider instances bound to a KeyWrapper, for each of the
// three ways this library reveals a DEK.
type CryptoProviderFactory interface {
	// Create builds a CryptoProvider that reveals wrapped through wrapper, refreshing every
	// expirySeconds.
	Create(wrapper KeyWrapper, wrapped []byte, expirySeconds int) (CryptoProvider, error)

	// CreateEphemeral generates a fresh DEK via wrapper.GenerateAndWrap and builds a
	// CryptoProvider around it, refreshing every expirySeconds.
	CreateEphemeral(wrapper KeyWrapper, expirySeconds int) (CryptoProvider, error)

	// CreateForPipeline builds a CryptoProvider around notWrapped directly - notWrapped is
	// already a plaintext DEK, never wrapped or unwrapped through wrapper.
	CreateForPipeline(wrapper KeyWrapper, notWrapped []byte) (CryptoProvider, error)
}
