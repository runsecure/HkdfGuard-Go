package keywrapping

import "fmt"

// NativeKmsError is returned when a call into the native HkdfGuard KMS library returns a
// non-ok status.
type NativeKmsError struct {
	message string
}

func newNativeKmsError(format string, args ...any) *NativeKmsError {
	return &NativeKmsError{message: fmt.Sprintf(format, args...)}
}

func (e *NativeKmsError) Error() string {
	return e.message
}
