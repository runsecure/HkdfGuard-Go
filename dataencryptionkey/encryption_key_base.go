package dataencryptionkey

import (
	"context"

	"github.com/runsecure/hkdfguard-go/abstractions"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"go.opentelemetry.io/otel/attribute"
)

// EncryptionKeyBase is an abstractions.DataEncryptionKey backed by one abstractions.CryptoProvider.
// Every operation calls straight through to provider, which owns revealing/refreshing its own key
// material - EncryptionKeyBase adds only the allocation sizing (via
// provider.GetEncryptedAllocationLength) and telemetry every concrete key in this package needs.
//
// KeyWrappedDataEncryptionKey and PipelineDataEncryptionKey (the C#/Java originals' two concrete
// subclasses) don't exist as distinct Go types: the "key-wrapped" case is just
// NewEncryptionKeyBase used directly, and PipelineDataEncryptionKey embeds *EncryptionKeyBase to
// add its own AsBytes/Close.
type EncryptionKeyBase struct {
	provider abstractions.CryptoProvider
}

var _ abstractions.DataEncryptionKey = (*EncryptionKeyBase)(nil)

// NewEncryptionKeyBase builds an EncryptionKeyBase backed by provider.
func NewEncryptionKeyBase(provider abstractions.CryptoProvider) *EncryptionKeyBase {
	return &EncryptionKeyBase{provider: provider}
}

// Encrypt implements abstractions.DataEncryptionKey.
func (k *EncryptionKeyBase) Encrypt(plaintext []byte, aad []byte) (result []byte, err error) {
	tel := diagnostics.DataProtection
	_, span := tel.Tracer().Start(context.Background(), diagnostics.ActivityNames.DataProtection.KeyWrappedKeyEncrypt)
	defer span.End()
	defer func() {
		if err != nil {
			tel.RecordException(span, err)
		}
	}()

	if tel.EnableSensitiveLogging() {
		tel.LogSensitiveOperation(span, diagnostics.ActivityNames.DataProtection.KeyWrappedKeyEncrypt,
			attribute.Int(diagnostics.AttributeNames.PlaintextLength, len(plaintext)),
			attribute.Int(diagnostics.AttributeNames.AadLength, len(aad)))
	}

	buffer := make([]byte, k.provider.GetEncryptedAllocationLength(len(plaintext)))
	written, err := k.provider.Encrypt(plaintext, aad, buffer)
	if err != nil {
		return nil, err
	}
	return buffer[:written], nil
}

// Decrypt implements abstractions.DataEncryptionKey.
func (k *EncryptionKeyBase) Decrypt(ciphertext []byte, aad []byte, result []byte) (n int, err error) {
	tel := diagnostics.DataProtection
	_, span := tel.Tracer().Start(context.Background(), diagnostics.ActivityNames.DataProtection.KeyWrappedKeyDecrypt)
	defer span.End()
	defer func() {
		if err != nil {
			tel.RecordException(span, err)
		}
	}()

	if tel.EnableSensitiveLogging() {
		tel.LogSensitiveOperation(span, diagnostics.ActivityNames.DataProtection.KeyWrappedKeyDecrypt,
			attribute.Int(diagnostics.AttributeNames.CiphertextLength, len(ciphertext)),
			attribute.Int(diagnostics.AttributeNames.AadLength, len(aad)))
	}

	return k.provider.Decrypt(ciphertext, aad, result)
}
