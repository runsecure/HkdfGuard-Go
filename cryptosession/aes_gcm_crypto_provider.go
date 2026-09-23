package cryptosession

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/runsecure/hkdfguard-go/abstractions"
	"github.com/runsecure/hkdfguard-go/diagnostics"
)

// ErrClosed is returned by AesGcmCryptoProvider.Encrypt/Decrypt once Close has been called.
var ErrClosed = errors.New("cryptosession: AesGcmCryptoProvider is closed")

// AesGcmCryptoProvider is a cached, key-bound AES-256-GCM abstractions.CryptoProvider: it reveals
// wrapped's plaintext DEK via keyWrapper once eagerly at construction, then proactively refreshes
// (re-reveals and rebuilds) it every expirySeconds in the background for as long as the provider
// is open, so a caller's Encrypt/Decrypt always runs against a currently-valid key without ever
// managing the refresh/expiry machinery itself.
type AesGcmCryptoProvider struct {
	keyWrapper    abstractions.KeyWrapper
	wrapped       []byte
	expirySeconds int

	mu      sync.RWMutex
	current *aesGcmCryptoSession
	closed  bool

	cancel context.CancelFunc
	done   chan struct{}
}

var _ abstractions.CryptoProvider = (*AesGcmCryptoProvider)(nil)

// NewAesGcmCryptoProvider builds a provider that reveals wrapped through keyWrapper, refreshing
// every expirySeconds (must be between 1 and 300 inclusive). The first reveal happens
// synchronously before this call returns, so a returned provider's Encrypt/Decrypt are
// immediately usable.
func NewAesGcmCryptoProvider(keyWrapper abstractions.KeyWrapper, wrapped []byte, expirySeconds int) (*AesGcmCryptoProvider, error) {
	if expirySeconds < 1 || expirySeconds > 300 {
		return nil, fmt.Errorf("cryptosession: expirySeconds must be between 1 and 300 seconds, was %d", expirySeconds)
	}

	p := &AesGcmCryptoProvider{
		keyWrapper:    keyWrapper,
		wrapped:       wrapped,
		expirySeconds: expirySeconds,
		done:          make(chan struct{}),
	}

	if err := p.refresh(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go p.runRefreshLoop(ctx)

	return p, nil
}

// Encrypt implements abstractions.CryptoProvider.
func (p *AesGcmCryptoProvider) Encrypt(plaintext []byte, aad []byte, result []byte) (int, error) {
	session, err := p.session()
	if err != nil {
		return 0, err
	}
	return session.encrypt(plaintext, aad, result)
}

// Decrypt implements abstractions.CryptoProvider.
func (p *AesGcmCryptoProvider) Decrypt(ciphertext []byte, aad []byte, result []byte) (int, error) {
	session, err := p.session()
	if err != nil {
		return 0, err
	}
	return session.decrypt(ciphertext, aad, result)
}

// Close implements abstractions.CryptoProvider (io.Closer). It stops the background refresh loop
// and zeroes the current session's key. Calling Close more than once is a no-op.
func (p *AesGcmCryptoProvider) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	current := p.current
	p.current = nil
	p.mu.Unlock()

	if p.cancel != nil {
		p.cancel()
		<-p.done
	}

	if current != nil {
		current.close()
	}
	return nil
}

func (p *AesGcmCryptoProvider) session() (*aesGcmCryptoSession, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, ErrClosed
	}
	return p.current, nil
}

// refresh reveals a fresh key via keyWrapper, builds a new session from it, and atomically swaps
// it in as current - the outgoing session (if any) is closed (its key zeroed) after the swap.
func (p *AesGcmCryptoProvider) refresh() error {
	key := make([]byte, keyLength)
	defer abstractions.ZeroMemory(key)

	n, err := p.keyWrapper.Decrypt(p.wrapped, key)
	if err != nil {
		return err
	}

	session, err := newAesGcmCryptoSession(key[:n])
	if err != nil {
		return err
	}

	p.mu.Lock()
	old := p.current
	p.current = session
	p.mu.Unlock()

	if old != nil {
		old.close()
	}
	return nil
}

// runRefreshLoop calls refresh every expirySeconds until ctx is cancelled (by Close), closing
// done on exit so Close can wait for this goroutine to actually stop before returning. Unlike
// the constructor's own synchronous refresh call, every refresh here is wrapped in a
// BackgroundRefresh span, matching the .NET/Java originals' background-only instrumentation.
func (p *AesGcmCryptoProvider) runRefreshLoop(ctx context.Context) {
	defer close(p.done)

	ticker := time.NewTicker(time.Duration(p.expirySeconds) * time.Second)
	defer ticker.Stop()

	tel := diagnostics.CryptoSessionAesGcm256

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, span := tel.Tracer().Start(ctx, diagnostics.ActivityNames.CryptoSessionAesGcm256.BackgroundRefresh)
			if err := p.refresh(); err != nil {
				tel.RecordException(span, err)
			}
			span.End()
		}
	}
}
