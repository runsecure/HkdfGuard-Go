package dataencryptionkey

import (
	"context"

	"github.com/runsecure/hkdfguard-go/abstractions"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"go.opentelemetry.io/otel/attribute"
)

// dataProtector is the default abstractions.DataProtector. Unexported: only
// KeyRing.CreateProtector can build one, so callers only ever see it as an
// abstractions.DataProtector, guaranteeing every instance is actually bound to a real KeyRing
// rather than constructed loose. name is used as this protector's AAD on every Encrypt/Decrypt,
// so a value protected under one name/purpose fails to decrypt under another. Encrypt resolves
// keyRing.GetCurrent() fresh on every call rather than capturing a version once at construction,
// so it always protects new data with whatever the ring's latest rotation is; Decrypt instead
// resolves whichever version the formatted ciphertext itself names, so old versions stay
// readable regardless.
type dataProtector struct {
	name           string
	aad            []byte
	keyRing        *KeyRing
	formatProvider abstractions.EncryptedFormatProvider
}

var _ abstractions.DataProtector = (*dataProtector)(nil)

func newDataProtector(name string, keyRing *KeyRing, formatProvider abstractions.EncryptedFormatProvider) *dataProtector {
	return &dataProtector{
		name:           name,
		aad:            []byte(name),
		keyRing:        keyRing,
		formatProvider: formatProvider,
	}
}

// Encrypt implements abstractions.DataProtector.
func (p *dataProtector) Encrypt(plaintext string) (result string, err error) {
	tel := diagnostics.DataProtection
	_, span := tel.Tracer().Start(context.Background(), diagnostics.ActivityNames.DataProtection.ProtectorEncrypt)
	defer span.End()
	defer func() {
		if err != nil {
			tel.RecordException(span, err)
		}
	}()

	if tel.EnableSensitiveLogging() {
		tel.LogSensitiveOperation(span, diagnostics.ActivityNames.DataProtection.ProtectorEncrypt,
			attribute.String(diagnostics.AttributeNames.Name, p.name),
			attribute.Int(diagnostics.AttributeNames.PlaintextLength, len(plaintext)))
	}

	version, key, err := p.keyRing.GetCurrent()
	if err != nil {
		return "", err
	}

	// plaintextBytes is zeroed as a side effect of the Encrypt call it's passed to.
	plaintextBytes := []byte(plaintext)
	encryptedBytes, err := key.Encrypt(plaintextBytes, p.aad)
	if err != nil {
		return "", err
	}

	return p.formatProvider.Format(abstractions.KeyTrackingValue{
		KeyVersion: version,
		Value:      encryptedBytes,
	}), nil
}

// Decrypt implements abstractions.DataProtector.
func (p *dataProtector) Decrypt(encrypted string, result []byte) (n int, err error) {
	tel := diagnostics.DataProtection
	_, span := tel.Tracer().Start(context.Background(), diagnostics.ActivityNames.DataProtection.ProtectorDecrypt)
	defer span.End()
	defer func() {
		if err != nil {
			tel.RecordException(span, err)
		}
	}()

	if tel.EnableSensitiveLogging() {
		tel.LogSensitiveOperation(span, diagnostics.ActivityNames.DataProtection.ProtectorDecrypt,
			attribute.String(diagnostics.AttributeNames.Name, p.name),
			attribute.Int(diagnostics.AttributeNames.EncryptedLength, len(encrypted)))
	}

	value, err := p.formatProvider.Parse(encrypted)
	if err != nil {
		return 0, err
	}

	key, err := p.keyRing.Get(value.KeyVersion)
	if err != nil {
		return 0, err
	}

	// AEAD ciphertext is always at least as long as the plaintext it encloses, so
	// len(value.Value) is a safe upper bound for the decrypted byte count.
	plaintextBytes := make([]byte, len(value.Value))
	defer abstractions.ZeroMemory(plaintextBytes)

	written, err := key.Decrypt(value.Value, p.aad, plaintextBytes)
	if err != nil {
		return 0, err
	}

	return copy(result, plaintextBytes[:written]), nil
}

// GetMaxDecryptedLength implements abstractions.DataProtector.
func (p *dataProtector) GetMaxDecryptedLength(encrypted string) (int, error) {
	return p.formatProvider.GetMaxDecryptedLength(encrypted)
}
