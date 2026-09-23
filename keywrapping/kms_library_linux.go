//go:build linux

package keywrapping

import (
	"fmt"

	"github.com/ebitengine/purego"
)

const linuxLibraryName = "libHkdfGuardKeyProtectionLinux.so"

// linuxKmsLibrary binds libHkdfGuardKeyProtectionLinux.so (see hkdfguard.h), which picks the
// strongest available provider on the host - TPM2 > PKCS#11 > external secret > software >
// ephemeral - to hold the per-service KEK. No Rust type, TPM handle, or OpenSSL structure ever
// crosses this boundary, and no panic ever crosses it either: every native call below returns a
// plain status code.
type linuxKmsLibrary struct {
	wrapDekFn            func(service string, dek []byte, dekLen int32, output []byte, outLen *int32) int32
	unwrapDekFn          func(service string, wrapped []byte, wrappedLen int32, output []byte, outLen *int32) int32
	generateAndWrapDekFn func(service string, output []byte, outLen *int32) int32
}

// newPlatformKmsLibrary loads linuxLibraryName and binds its three functions. It is the only
// symbol every kms_library_<goos>.go file defines under the same name, so native_host.go can
// call it without knowing (at compile time) which platform it's building for.
func newPlatformKmsLibrary() (kmsLibrary, error) {
	handle, err := purego.Dlopen(linuxLibraryName, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, fmt.Errorf("failed to load %s: %w", linuxLibraryName, err)
	}

	lib := &linuxKmsLibrary{}
	purego.RegisterLibFunc(&lib.wrapDekFn, handle, "hkdfguard_wrap_dek")
	purego.RegisterLibFunc(&lib.unwrapDekFn, handle, "hkdfguard_unwrap_dek")
	purego.RegisterLibFunc(&lib.generateAndWrapDekFn, handle, "hkdfguard_generate_and_wrap_dek")
	return lib, nil
}

func (l *linuxKmsLibrary) wrapDek(service string, dek []byte, destination []byte) nativeCallResult {
	outLen := int32(len(destination))
	status := l.wrapDekFn(service, dek, int32(len(dek)), destination, &outLen)
	return nativeCallResult{status: status, bytesWritten: outLen}
}

func (l *linuxKmsLibrary) unwrapDek(service string, wrapped []byte, destination []byte) nativeCallResult {
	outLen := int32(len(destination))
	status := l.unwrapDekFn(service, wrapped, int32(len(wrapped)), destination, &outLen)
	return nativeCallResult{status: status, bytesWritten: outLen}
}

func (l *linuxKmsLibrary) generateAndWrapDek(service string, destination []byte) nativeCallResult {
	outLen := int32(len(destination))
	status := l.generateAndWrapDekFn(service, destination, &outLen)
	return nativeCallResult{status: status, bytesWritten: outLen}
}
