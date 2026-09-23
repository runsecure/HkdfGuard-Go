package dataencryptionkey

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/runsecure/hkdfguard-go/abstractions"
	"github.com/runsecure/hkdfguard-go/diagnostics"
	"go.opentelemetry.io/otel/attribute"
)

const (
	encPrefix     = "enc"
	delimiter     = "::"
	versionPrefix = "v"
)

// DefaultFormatProvider is the default abstractions.EncryptedFormatProvider: formats/parses
// "enc::v<version>::<base64>", using Go's standard encoding/base64 directly (unlike the C#/Java
// originals, there's no separate base64 helper type here - Go's stdlib already covers exactly
// what this needs).
type DefaultFormatProvider struct{}

var _ abstractions.EncryptedFormatProvider = DefaultFormatProvider{}

// Format implements abstractions.EncryptedFormatProvider.
func (DefaultFormatProvider) Format(value abstractions.KeyTrackingValue) string {
	tel := diagnostics.DataProtection
	_, span := tel.Tracer().Start(context.Background(), diagnostics.ActivityNames.DataProtection.FormatProviderFormat)
	defer span.End()

	if tel.EnableSensitiveLogging() {
		tel.LogSensitiveOperation(span, diagnostics.ActivityNames.DataProtection.FormatProviderFormat,
			attribute.Int(diagnostics.AttributeNames.KeyVersion, value.KeyVersion),
			attribute.Int(diagnostics.AttributeNames.ValueLength, len(value.Value)))
	}

	return encPrefix + delimiter + versionPrefix + strconv.Itoa(value.KeyVersion) + delimiter + base64.StdEncoding.EncodeToString(value.Value)
}

// Parse implements abstractions.EncryptedFormatProvider.
func (DefaultFormatProvider) Parse(encrypted string) (value abstractions.KeyTrackingValue, err error) {
	tel := diagnostics.DataProtection
	_, span := tel.Tracer().Start(context.Background(), diagnostics.ActivityNames.DataProtection.FormatProviderParse)
	defer span.End()
	defer func() {
		if err != nil {
			tel.RecordException(span, err)
		}
	}()

	if tel.EnableSensitiveLogging() {
		tel.LogSensitiveOperation(span, diagnostics.ActivityNames.DataProtection.FormatProviderParse,
			attribute.Int(diagnostics.AttributeNames.EncryptedLength, len(encrypted)))
	}

	version, base64Segment, ok := parseSegments(encrypted)
	if !ok {
		return abstractions.KeyTrackingValue{}, invalidFormatError()
	}

	decoded, decodeErr := base64.StdEncoding.DecodeString(base64Segment)
	if decodeErr != nil {
		return abstractions.KeyTrackingValue{}, fmt.Errorf("dataencryptionkey: encrypted value is not valid base64: %w", decodeErr)
	}

	return abstractions.KeyTrackingValue{KeyVersion: version, Value: decoded}, nil
}

// GetMaxDecryptedLength implements abstractions.EncryptedFormatProvider.
func (DefaultFormatProvider) GetMaxDecryptedLength(encrypted string) (n int, err error) {
	tel := diagnostics.DataProtection
	_, span := tel.Tracer().Start(context.Background(), diagnostics.ActivityNames.DataProtection.FormatProviderGetMaxDecryptedLength)
	defer span.End()
	defer func() {
		if err != nil {
			tel.RecordException(span, err)
		}
	}()

	if tel.EnableSensitiveLogging() {
		tel.LogSensitiveOperation(span, diagnostics.ActivityNames.DataProtection.FormatProviderGetMaxDecryptedLength,
			attribute.Int(diagnostics.AttributeNames.EncryptedLength, len(encrypted)))
	}

	_, base64Segment, ok := parseSegments(encrypted)
	if !ok {
		return 0, invalidFormatError()
	}
	if len(base64Segment)%4 != 0 {
		return 0, errors.New("dataencryptionkey: encrypted value is not valid base64")
	}

	// DecodedLen is an upper bound based on length alone (it doesn't account for padding), which
	// is exactly what's wanted here: AEAD ciphertext is always at least as long as the plaintext
	// it encloses, so the actual decrypted length is this value or less - always safe to size a
	// result buffer to what this returns.
	return base64.StdEncoding.DecodedLen(len(base64Segment)), nil
}

func invalidFormatError() error {
	return fmt.Errorf("dataencryptionkey: invalid encrypted format, expected '%s%sv<version>%s<base64>'", encPrefix, delimiter, delimiter)
}

// parseSegments splits encrypted into its version and base64 segments, reporting whether it
// matched "enc::v<version>::<base64>". Shared by Parse and GetMaxDecryptedLength so both agree
// on exactly what counts as well-formed - only GetMaxDecryptedLength skips the actual base64
// decode/allocation.
func parseSegments(encrypted string) (version int, base64Segment string, ok bool) {
	firstIdx := strings.Index(encrypted, delimiter)
	if firstIdx < 0 {
		return 0, "", false
	}

	afterPrefix := encrypted[firstIdx+len(delimiter):]
	secondIdx := strings.Index(afterPrefix, delimiter)
	if secondIdx < 0 {
		return 0, "", false
	}

	prefix := encrypted[:firstIdx]
	versionSegment := afterPrefix[:secondIdx]
	base64Segment = afterPrefix[secondIdx+len(delimiter):]

	if prefix != encPrefix || !strings.HasPrefix(versionSegment, versionPrefix) {
		return 0, "", false
	}

	version, convErr := strconv.Atoi(versionSegment[len(versionPrefix):])
	if convErr != nil {
		return 0, "", false
	}

	return version, base64Segment, true
}
