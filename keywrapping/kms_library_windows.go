//go:build windows

package keywrapping

import (
	"fmt"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/windows"
)

const windowsLibraryName = "HkdfGuard.Kms.Windows.v1.dll"

// windowsKmsLibrary binds HkdfGuard.Kms.Windows.v1.dll (see hkdfguard.h), which holds the
// per-service KEK as a persistent, machine-wide-scoped, non-exportable P-256 key in the
// Microsoft Platform Crypto Provider (TPM/vTPM) when available, or the Microsoft Software Key
// Storage Provider otherwise.
type windowsKmsLibrary struct {
	wrapDekFn            func(service string, dek []byte, dekLen int32, output []byte, outLen *int32) int32
	unwrapDekFn          func(service string, wrapped []byte, wrappedLen int32, output []byte, outLen *int32) int32
	generateAndWrapDekFn func(service string, output []byte, outLen *int32) int32
}

// newPlatformKmsLibrary loads windowsLibraryName and binds its three functions. It is the only
// symbol every kms_library_<goos>.go file defines under the same name, so native_host.go can
// call it without knowing (at compile time) which platform it's building for.
func newPlatformKmsLibrary() (kmsLibrary, error) {
	handle, err := windows.LoadLibrary(windowsLibraryName)
	if err != nil {
		return nil, fmt.Errorf("failed to load %s: %w", windowsLibraryName, err)
	}

	lib := &windowsKmsLibrary{}
	purego.RegisterLibFunc(&lib.wrapDekFn, uintptr(handle), "hkdfguard_wrap_dek")
	purego.RegisterLibFunc(&lib.unwrapDekFn, uintptr(handle), "hkdfguard_unwrap_dek")
	purego.RegisterLibFunc(&lib.generateAndWrapDekFn, uintptr(handle), "hkdfguard_generate_and_wrap_dek")
	return lib, nil
}

func (l *windowsKmsLibrary) wrapDek(service string, dek []byte, destination []byte) nativeCallResult {
	outLen := int32(len(destination))
	status := l.wrapDekFn(service, dek, int32(len(dek)), destination, &outLen)
	return nativeCallResult{status: status, bytesWritten: outLen}
}

func (l *windowsKmsLibrary) unwrapDek(service string, wrapped []byte, destination []byte) nativeCallResult {
	outLen := int32(len(destination))
	status := l.unwrapDekFn(service, wrapped, int32(len(wrapped)), destination, &outLen)
	return nativeCallResult{status: status, bytesWritten: outLen}
}

func (l *windowsKmsLibrary) generateAndWrapDek(service string, destination []byte) nativeCallResult {
	outLen := int32(len(destination))
	status := l.generateAndWrapDekFn(service, destination, &outLen)
	return nativeCallResult{status: status, bytesWritten: outLen}
}
