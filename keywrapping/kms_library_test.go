package keywrapping

import "testing"

// These tests only touch package-level constants - the ones for all three platforms are defined
// in kms_library.go without build tags for exactly this reason, unlike the platform-specific
// dlopen/binding code in kms_library_linux.go/kms_library_darwin.go/kms_library_windows.go,
// which is only compiled in on its own GOOS. See native_hkdf_key_wrapper_v1_test.go for
// behavioral coverage, exercised against a fake kmsLibrary instead of a real platform binding.

func TestConstants(t *testing.T) {
	if dekLength != 32 {
		t.Errorf("dekLength = %d, want 32", dekLength)
	}
	if ok != 0 {
		t.Errorf("ok = %d, want 0", ok)
	}
}

func TestLinuxErrorConstants(t *testing.T) {
	cases := map[string]struct {
		got, want int32
	}{
		"ErrInvalidArgument":     {linuxErrInvalidArgument, -1},
		"ErrBufferTooSmall":      {linuxErrBufferTooSmall, -2},
		"ErrProviderUnavailable": {linuxErrProviderUnavailable, -3},
		"ErrProviderError":       {linuxErrProviderError, -4},
		"ErrCryptoError":         {linuxErrCryptoError, -5},
		"ErrInternalError":       {linuxErrInternalError, -6},
		"ErrInvalidUtf8":         {linuxErrInvalidUtf8, -7},
		"ErrMissingServiceName":  {linuxErrMissingServiceName, -8},
	}
	for name, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", name, c.got, c.want)
		}
	}
}

func TestMacOSErrorConstants(t *testing.T) {
	cases := map[string]struct {
		got, want int32
	}{
		"ErrInvalidInputLength":       {macOSErrInvalidInputLength, -1},
		"ErrOutputBufferTooSmall":     {macOSErrOutputBufferTooSmall, -2},
		"ErrKeyUnavailable":           {macOSErrKeyUnavailable, -3},
		"ErrPublicKeyUnavailable":     {macOSErrPublicKeyUnavailable, -4},
		"ErrEncryptionFailed":         {macOSErrEncryptionFailed, -5},
		"ErrDecryptionFailed":         {macOSErrDecryptionFailed, -6},
		"ErrUnexpectedOutputLength":   {macOSErrUnexpectedOutputLength, -7},
		"ErrMissingServiceIdentifier": {macOSErrMissingServiceIdentifier, -8},
	}
	for name, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", name, c.got, c.want)
		}
	}
}

func TestWindowsErrorConstants(t *testing.T) {
	cases := map[string]struct {
		got, want int32
	}{
		"ErrInvalidArg":     {windowsErrInvalidArg, -1},
		"ErrBufferTooSmall": {windowsErrBufferTooSmall, -2},
		"ErrProvider":       {windowsErrProvider, -3},
		"ErrCrypto":         {windowsErrCrypto, -4},
		"ErrAuthFailed":     {windowsErrAuthFailed, -5},
		"ErrMalformed":      {windowsErrMalformed, -6},
		"ErrInternal":       {windowsErrInternal, -7},
	}
	for name, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", name, c.got, c.want)
		}
	}
}
