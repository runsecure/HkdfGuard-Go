package cryptosession

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/runsecure/hkdfguard-go/abstractions"
)

// factoryFakeKeyWrapper is an abstractions.KeyWrapper that always reveals/generates the same
// fixed key, tracking how many times Decrypt/GenerateAndWrap were called - isolates
// AesGcmCryptoProviderFactory tests from any real native KMS machinery.
type factoryFakeKeyWrapper struct {
	key                      []byte
	decryptCallCount         int
	generateAndWrapCallCount int
	decryptErr               error
}

var _ abstractions.KeyWrapper = (*factoryFakeKeyWrapper)(nil)

func newFactoryFakeKeyWrapper() *factoryFakeKeyWrapper {
	key := make([]byte, keyLength)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return &factoryFakeKeyWrapper{key: key}
}

func (w *factoryFakeKeyWrapper) Encrypt(plaintext []byte, result []byte) (int, error) {
	return 0, errors.New("factoryFakeKeyWrapper: Encrypt not supported")
}

func (w *factoryFakeKeyWrapper) Decrypt(wrapped []byte, result []byte) (int, error) {
	w.decryptCallCount++
	if w.decryptErr != nil {
		return 0, w.decryptErr
	}
	return copy(result, w.key), nil
}

func (w *factoryFakeKeyWrapper) GenerateAndWrap(result []byte) (int, error) {
	w.generateAndWrapCallCount++
	return copy(result, w.key), nil
}

var cryptoProviderFactory = AesGcmCryptoProviderFactory{}

func TestAesGcmCryptoProviderFactory_Create_ProducesAWorkingProvider(t *testing.T) {
	wrapper := newFactoryFakeKeyWrapper()
	provider, err := cryptoProviderFactory.Create(wrapper, []byte("wrapped"), 60)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	defer provider.Close()

	plaintext := []byte("top secret")
	encrypted := make([]byte, provider.GetEncryptedAllocationLength(len(plaintext)))
	written, err := provider.Encrypt(plaintext, nil, encrypted)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted := make([]byte, len("top secret"))
	if _, err := provider.Decrypt(encrypted[:written], nil, decrypted); err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if string(decrypted) != "top secret" {
		t.Errorf("decrypted = %q, want %q", decrypted, "top secret")
	}
}

func TestAesGcmCryptoProviderFactory_CreateEphemeral_CallsGenerateAndWrapExactlyOnce(t *testing.T) {
	wrapper := newFactoryFakeKeyWrapper()
	provider, err := cryptoProviderFactory.CreateEphemeral(wrapper, 60)
	if err != nil {
		t.Fatalf("CreateEphemeral() error = %v", err)
	}
	defer provider.Close()

	if wrapper.generateAndWrapCallCount != 1 {
		t.Errorf("generateAndWrapCallCount = %d, want 1", wrapper.generateAndWrapCallCount)
	}
}

func TestAesGcmCryptoProviderFactory_CreateEphemeral_ProducesAWorkingProvider(t *testing.T) {
	wrapper := newFactoryFakeKeyWrapper()
	provider, err := cryptoProviderFactory.CreateEphemeral(wrapper, 60)
	if err != nil {
		t.Fatalf("CreateEphemeral() error = %v", err)
	}
	defer provider.Close()

	plaintext := []byte("top secret")
	encrypted := make([]byte, provider.GetEncryptedAllocationLength(len(plaintext)))
	written, err := provider.Encrypt(plaintext, nil, encrypted)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted := make([]byte, len(plaintext))
	n, err := provider.Decrypt(encrypted[:written], nil, decrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if string(decrypted[:n]) != "top secret" {
		t.Errorf("decrypted = %q, want %q", decrypted[:n], "top secret")
	}
}

func TestAesGcmCryptoProviderFactory_CreateForPipeline_NeverCallsTheKeyWrapper(t *testing.T) {
	// CreateForPipeline uses the supplied bytes directly as the AES key - there is nothing to
	// wrap/unwrap, so the wrapper it's handed should never be invoked.
	wrapper := newFactoryFakeKeyWrapper()
	wrapper.decryptErr = errors.New("should not be called")
	dek := make([]byte, keyLength)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}

	provider, err := cryptoProviderFactory.CreateForPipeline(wrapper, dek)
	if err != nil {
		t.Fatalf("CreateForPipeline() error = %v", err)
	}
	defer provider.Close()

	if wrapper.decryptCallCount != 0 {
		t.Errorf("decryptCallCount = %d, want 0", wrapper.decryptCallCount)
	}
	if wrapper.generateAndWrapCallCount != 0 {
		t.Errorf("generateAndWrapCallCount = %d, want 0", wrapper.generateAndWrapCallCount)
	}
}

func TestAesGcmCryptoProviderFactory_CreateForPipeline_ProducesAWorkingProvider(t *testing.T) {
	wrapper := newFactoryFakeKeyWrapper()
	dek := make([]byte, keyLength)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}

	provider, err := cryptoProviderFactory.CreateForPipeline(wrapper, dek)
	if err != nil {
		t.Fatalf("CreateForPipeline() error = %v", err)
	}
	defer provider.Close()

	plaintext := []byte("top secret")
	encrypted := make([]byte, provider.GetEncryptedAllocationLength(len(plaintext)))
	written, err := provider.Encrypt(plaintext, nil, encrypted)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted := make([]byte, len(plaintext))
	n, err := provider.Decrypt(encrypted[:written], nil, decrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if string(decrypted[:n]) != "top secret" {
		t.Errorf("decrypted = %q, want %q", decrypted[:n], "top secret")
	}
}

func TestAesGcmCryptoProviderFactory_CreateForPipeline_CloseDoesNotError(t *testing.T) {
	// Regression guard: the pipeline-only AesGcmCryptoProvider construction path must leave a
	// usable (nil) cancel func/done channel, not ones that crash or block Close.
	wrapper := newFactoryFakeKeyWrapper()
	dek := make([]byte, keyLength)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}

	provider, err := cryptoProviderFactory.CreateForPipeline(wrapper, dek)
	if err != nil {
		t.Fatalf("CreateForPipeline() error = %v", err)
	}

	if err := provider.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}
