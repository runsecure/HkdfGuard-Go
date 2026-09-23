package cryptosession

import (
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/runsecure/hkdfguard-go/abstractions"
)

// fakeKeyWrapper is an abstractions.KeyWrapper that always reveals a fresh random key, tracking
// how many times Decrypt was called - isolates AesGcmCryptoProvider tests from any real native
// KMS machinery. Mirrors the .NET original's FakeKeyWrapper test helper.
type fakeKeyWrapper struct {
	mu               sync.Mutex
	decryptCallCount int
	decryptErr       error
}

var _ abstractions.KeyWrapper = (*fakeKeyWrapper)(nil)

func (f *fakeKeyWrapper) Encrypt(plaintext []byte, result []byte) (int, error) {
	return 0, errors.New("fakeKeyWrapper: Encrypt not supported")
}

func (f *fakeKeyWrapper) Decrypt(wrapped []byte, result []byte) (int, error) {
	f.mu.Lock()
	f.decryptCallCount++
	f.mu.Unlock()

	if f.decryptErr != nil {
		return 0, f.decryptErr
	}

	if _, err := rand.Read(result[:keyLength]); err != nil {
		return 0, err
	}
	return keyLength, nil
}

func (f *fakeKeyWrapper) GenerateAndWrap(result []byte) (int, error) {
	return 0, errors.New("fakeKeyWrapper: GenerateAndWrap not supported")
}

func (f *fakeKeyWrapper) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.decryptCallCount
}

func TestNewAesGcmCryptoProvider_BuildsInitialSessionEagerly(t *testing.T) {
	wrapper := &fakeKeyWrapper{}

	provider, err := NewAesGcmCryptoProvider(wrapper, []byte("wrapped"), 60)
	if err != nil {
		t.Fatalf("NewAesGcmCryptoProvider() error = %v", err)
	}
	defer provider.Close()

	if got := wrapper.callCount(); got != 1 {
		t.Errorf("decryptCallCount = %d, want 1", got)
	}
}

func TestNewAesGcmCryptoProvider_WhenKeyWrapperFails_Errors(t *testing.T) {
	wrapper := &fakeKeyWrapper{decryptErr: errors.New("reveal failed")}

	if _, err := NewAesGcmCryptoProvider(wrapper, []byte("wrapped"), 60); err == nil {
		t.Fatal("NewAesGcmCryptoProvider() error = nil, want error")
	}
}

func TestNewAesGcmCryptoProvider_WithExpirySecondsOutOfRange_Errors(t *testing.T) {
	for _, expirySeconds := range []int{0, -1, 301} {
		wrapper := &fakeKeyWrapper{}
		if _, err := NewAesGcmCryptoProvider(wrapper, []byte("wrapped"), expirySeconds); err == nil {
			t.Errorf("NewAesGcmCryptoProvider(expirySeconds=%d) error = nil, want error", expirySeconds)
		}
	}
}

func TestAesGcmCryptoProvider_BackgroundLoop_ProactivelyRefreshesTheSession(t *testing.T) {
	wrapper := &fakeKeyWrapper{}
	provider, err := NewAesGcmCryptoProvider(wrapper, []byte("wrapped"), 1)
	if err != nil {
		t.Fatalf("NewAesGcmCryptoProvider() error = %v", err)
	}
	defer provider.Close()

	// No Encrypt/Decrypt call at all - only the constructor's eager build (callCount == 1) and
	// the background ticker, firing every expirySeconds, should have run by now.
	time.Sleep(1500 * time.Millisecond)

	if got := wrapper.callCount(); got != 2 {
		t.Errorf("decryptCallCount = %d, want 2", got)
	}
}

func TestAesGcmCryptoProvider_Close_StopsTheBackgroundLoop(t *testing.T) {
	wrapper := &fakeKeyWrapper{}
	provider, err := NewAesGcmCryptoProvider(wrapper, []byte("wrapped"), 1)
	if err != nil {
		t.Fatalf("NewAesGcmCryptoProvider() error = %v", err)
	}

	if err := provider.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	time.Sleep(1500 * time.Millisecond)

	// Only the constructor's eager build - the ticker must not have fired after Close.
	if got := wrapper.callCount(); got != 1 {
		t.Errorf("decryptCallCount = %d, want 1", got)
	}
}

func TestAesGcmCryptoProvider_EncryptDecrypt_RoundTrips(t *testing.T) {
	wrapper := &fakeKeyWrapper{}
	provider, err := NewAesGcmCryptoProvider(wrapper, []byte("wrapped"), 60)
	if err != nil {
		t.Fatalf("NewAesGcmCryptoProvider() error = %v", err)
	}
	defer provider.Close()

	plaintext := []byte("hello world")
	encrypted := make([]byte, len(plaintext)+nonceSize+tagSize)
	if _, err := provider.Encrypt(plaintext, nil, encrypted); err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted := make([]byte, 11)
	n, err := provider.Decrypt(encrypted, nil, decrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if string(decrypted[:n]) != "hello world" {
		t.Errorf("decrypted = %q, want %q", decrypted[:n], "hello world")
	}
}

func TestAesGcmCryptoProvider_AfterClose_EncryptDecryptReturnErrClosed(t *testing.T) {
	wrapper := &fakeKeyWrapper{}
	provider, err := NewAesGcmCryptoProvider(wrapper, []byte("wrapped"), 60)
	if err != nil {
		t.Fatalf("NewAesGcmCryptoProvider() error = %v", err)
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if _, err := provider.Encrypt([]byte("hello"), nil, make([]byte, 64)); !errors.Is(err, ErrClosed) {
		t.Errorf("Encrypt() error = %v, want ErrClosed", err)
	}
	if _, err := provider.Decrypt(make([]byte, 64), nil, make([]byte, 64)); !errors.Is(err, ErrClosed) {
		t.Errorf("Decrypt() error = %v, want ErrClosed", err)
	}
}

func TestAesGcmCryptoProvider_Close_IsIdempotent(t *testing.T) {
	wrapper := &fakeKeyWrapper{}
	provider, err := NewAesGcmCryptoProvider(wrapper, []byte("wrapped"), 60)
	if err != nil {
		t.Fatalf("NewAesGcmCryptoProvider() error = %v", err)
	}

	if err := provider.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
