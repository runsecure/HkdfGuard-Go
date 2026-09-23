package keywrapping

import "sync"

// getLibrary resolves the current OS's native HkdfGuard KMS library exactly once per process
// (binding the wrong platform's library would fail on first native call anyway, so there's
// nothing to gain by re-resolving per instance), caching whichever result - library or error -
// newPlatformKmsLibrary produced on the first call.
//
// Unlike the C#/Java ports, there's no runtime platform-name string to switch on here: Go
// resolves which platform's newPlatformKmsLibrary gets compiled in via build constraints (see
// kms_library_linux.go, kms_library_darwin.go, kms_library_windows.go, and the
// kms_library_other.go fallback), so the selection already happened before this code runs.
var getLibrary = sync.OnceValues(newPlatformKmsLibrary)
