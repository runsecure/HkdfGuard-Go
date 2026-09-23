//go:build darwin

package keywrapping

import (
	"fmt"

	"github.com/ebitengine/purego"
)

const macOSLibraryName = "HkdfGuard.Kms.MacOS.v1.dylib"

// macOSKmsLibrary binds HkdfGuard.Kms.MacOS.v1.dylib (see HkdfGuardKeyProtectionEnclave.h),
// which holds the per-service KEK as a Secure Enclave key. Each distinct service string gets its
// own, independent Secure Enclave key - wrapping under one service's identifier and unwrapping
// under a different one fails by design (macOSErrDecryptionFailed).
type macOSKmsLibrary struct {
	wrapDekFn            func(service string, dek []byte, dekLen int32, output []byte, outLen *int32) int32
	unwrapDekFn          func(service string, wrapped []byte, wrappedLen int32, output []byte, outLen *int32) int32
	generateAndWrapDekFn func(service string, output []byte, outLen *int32) int32
}

// newPlatformKmsLibrary loads macOSLibraryName and binds its three functions. It is the only
// symbol every kms_library_<goos>.go file defines under the same name, so native_host.go can
// call it without knowing (at compile time) which platform it's building for.
func newPlatformKmsLibrary() (kmsLibrary, error) {
	handle, err := purego.Dlopen(macOSLibraryName, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, fmt.Errorf("failed to load %s: %w", macOSLibraryName, err)
	}

	lib := &macOSKmsLibrary{}
	purego.RegisterLibFunc(&lib.wrapDekFn, handle, "hkdfguard_wrap_dek")
	purego.RegisterLibFunc(&lib.unwrapDekFn, handle, "hkdfguard_unwrap_dek")
	purego.RegisterLibFunc(&lib.generateAndWrapDekFn, handle, "hkdfguard_generate_and_wrap_dek")
	return lib, nil
}

func (l *macOSKmsLibrary) wrapDek(service string, dek []byte, destination []byte) nativeCallResult {
	outLen := int32(len(destination))
	status := l.wrapDekFn(service, dek, int32(len(dek)), destination, &outLen)
	return nativeCallResult{status: status, bytesWritten: outLen}
}

func (l *macOSKmsLibrary) unwrapDek(service string, wrapped []byte, destination []byte) nativeCallResult {
	outLen := int32(len(destination))
	status := l.unwrapDekFn(service, wrapped, int32(len(wrapped)), destination, &outLen)
	return nativeCallResult{status: status, bytesWritten: outLen}
}

func (l *macOSKmsLibrary) generateAndWrapDek(service string, destination []byte) nativeCallResult {
	outLen := int32(len(destination))
	status := l.generateAndWrapDekFn(service, destination, &outLen)
	return nativeCallResult{status: status, bytesWritten: outLen}
}
