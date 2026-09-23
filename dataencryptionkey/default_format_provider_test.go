package dataencryptionkey

import (
	"bytes"
	"testing"

	"github.com/runsecure/hkdfguard-go/abstractions"
)

func TestDefaultFormatProvider_FormatParse_RoundTrips(t *testing.T) {
	p := DefaultFormatProvider{}
	value := abstractions.KeyTrackingValue{KeyVersion: 3, Value: []byte{1, 2, 3, 4, 5}}

	formatted := p.Format(value)
	parsed, err := p.Parse(formatted)

	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.KeyVersion != value.KeyVersion {
		t.Errorf("KeyVersion = %d, want %d", parsed.KeyVersion, value.KeyVersion)
	}
	if !bytes.Equal(parsed.Value, value.Value) {
		t.Errorf("Value = %v, want %v", parsed.Value, value.Value)
	}
}

func TestDefaultFormatProvider_Format_UsesExpectedPrefix(t *testing.T) {
	p := DefaultFormatProvider{}

	formatted := p.Format(abstractions.KeyTrackingValue{KeyVersion: 1, Value: []byte("x")})

	const want = "enc::v1::eA=="
	if formatted != want {
		t.Errorf("Format() = %q, want %q", formatted, want)
	}
}

func TestDefaultFormatProvider_Parse_InvalidFormat_ReturnsError(t *testing.T) {
	p := DefaultFormatProvider{}

	tests := []string{
		"",
		"not-encrypted-at-all",
		"enc::novprefix::eA==",
		"wrong::v1::eA==",
	}
	for _, encrypted := range tests {
		if _, err := p.Parse(encrypted); err == nil {
			t.Errorf("Parse(%q) error = nil, want non-nil", encrypted)
		}
	}
}

func TestDefaultFormatProvider_Parse_InvalidBase64_ReturnsError(t *testing.T) {
	p := DefaultFormatProvider{}

	if _, err := p.Parse("enc::v1::not valid base64!!"); err == nil {
		t.Error("Parse() error = nil, want non-nil")
	}
}

func TestDefaultFormatProvider_GetMaxDecryptedLength_ReturnsUpperBound(t *testing.T) {
	p := DefaultFormatProvider{}
	value := abstractions.KeyTrackingValue{KeyVersion: 1, Value: []byte("hello world")}
	formatted := p.Format(value)

	maxLength, err := p.GetMaxDecryptedLength(formatted)
	if err != nil {
		t.Fatalf("GetMaxDecryptedLength() error = %v", err)
	}
	if maxLength < len(value.Value) {
		t.Errorf("GetMaxDecryptedLength() = %d, want >= %d", maxLength, len(value.Value))
	}
}
