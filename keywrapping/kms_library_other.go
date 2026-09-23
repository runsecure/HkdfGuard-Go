//go:build !linux && !darwin && !windows

package keywrapping

import (
	"fmt"
	"runtime"
)

// newPlatformKmsLibrary is the fallback compiled in for every GOOS this package has no native
// KMS binding for. It is the only symbol every kms_library_<goos>.go file defines under the same
// name, so native_host.go can call it without knowing (at compile time) which platform it's
// building for.
func newPlatformKmsLibrary() (kmsLibrary, error) {
	return nil, fmt.Errorf("hkdfguard/keywrapping has no native KMS library for GOOS=%s", runtime.GOOS)
}
