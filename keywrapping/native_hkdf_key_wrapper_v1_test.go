package keywrapping

import (
	"bytes"
	"testing"
)

// fakeKmsLibrary is a kmsLibrary test double - the real platform bindings call into a
// vendor-supplied native library this repo doesn't (and can't) bundle. See kms_library_test.go
// for the one thing that's safe to assert about the real platform implementations without
// loading them: their constants.
type fakeKmsLibrary struct {
	wrapDekStatus            int32
	unwrapDekStatus          int32
	generateAndWrapDekStatus int32

	wrapPayloadToEmit            []byte
	unwrapPayloadToEmit          []byte
	generateAndWrapPayloadToEmit []byte

	lastService       string
	lastWrapPlaintext []byte
	lastUnwrapWrapped []byte

	wrapCallCount            int
	unwrapCallCount          int
	generateAndWrapCallCount int
}

func newFakeKmsLibrary() *fakeKmsLibrary {
	return &fakeKmsLibrary{
		wrapDekStatus:            ok,
		unwrapDekStatus:          ok,
		generateAndWrapDekStatus: ok,
	}
}

func (f *fakeKmsLibrary) wrapDek(service string, dek []byte, destination []byte) nativeCallResult {
	f.wrapCallCount++
	f.lastService = service
	f.lastWrapPlaintext = append([]byte(nil), dek...)

	if f.wrapDekStatus != ok {
		return nativeCallResult{status: f.wrapDekStatus, bytesWritten: 0}
	}

	payload := f.wrapPayloadToEmit
	if payload == nil {
		payload = dek
	}
	copy(destination, payload)
	return nativeCallResult{status: ok, bytesWritten: int32(len(payload))}
}

func (f *fakeKmsLibrary) unwrapDek(service string, wrapped []byte, destination []byte) nativeCallResult {
	f.unwrapCallCount++
	f.lastService = service
	f.lastUnwrapWrapped = append([]byte(nil), wrapped...)

	if f.unwrapDekStatus != ok {
		return nativeCallResult{status: f.unwrapDekStatus, bytesWritten: 0}
	}

	payload := f.unwrapPayloadToEmit
	if payload == nil {
		payload = wrapped
	}
	copy(destination, payload)
	return nativeCallResult{status: ok, bytesWritten: int32(len(payload))}
}

func (f *fakeKmsLibrary) generateAndWrapDek(service string, destination []byte) nativeCallResult {
	f.generateAndWrapCallCount++
	f.lastService = service

	if f.generateAndWrapDekStatus != ok {
		return nativeCallResult{status: f.generateAndWrapDekStatus, bytesWritten: 0}
	}

	payload := f.generateAndWrapPayloadToEmit
	if payload == nil {
		payload = make([]byte, 64)
	}
	copy(destination, payload)
	return nativeCallResult{status: ok, bytesWritten: int32(len(payload))}
}

func TestNativeHkdfKeyWrapperV1_Encrypt_DelegatesToLibrary(t *testing.T) {
	library := newFakeKmsLibrary()
	library.wrapPayloadToEmit = []byte{10, 20, 30, 40}
	wrapper := newNativeHkdfKeyWrapperV1("service-a", library)

	plaintext := []byte{1, 2, 3, 4, 5}
	result := make([]byte, 16)
	written, err := wrapper.Encrypt(plaintext, result)

	if err != nil {
		t.Fatalf("Encrypt() error = %v, want nil", err)
	}
	if written != 4 {
		t.Errorf("Encrypt() = %d, want 4", written)
	}
	if library.wrapCallCount != 1 {
		t.Errorf("wrapCallCount = %d, want 1", library.wrapCallCount)
	}
	if library.lastService != "service-a" {
		t.Errorf("lastService = %q, want %q", library.lastService, "service-a")
	}
	if !bytes.Equal(library.lastWrapPlaintext, plaintext) {
		t.Errorf("lastWrapPlaintext = %v, want %v", library.lastWrapPlaintext, plaintext)
	}
	if !bytes.Equal(result[:4], []byte{10, 20, 30, 40}) {
		t.Errorf("result[:4] = %v, want [10 20 30 40]", result[:4])
	}
}

func TestNativeHkdfKeyWrapperV1_Encrypt_WhenLibraryFails_ReturnsNativeKmsError(t *testing.T) {
	for _, status := range []int32{-1, -2, -7} {
		library := newFakeKmsLibrary()
		library.wrapDekStatus = status
		wrapper := newNativeHkdfKeyWrapperV1("service-d", library)

		_, err := wrapper.Encrypt([]byte{1, 2, 3}, make([]byte, 8))

		if _, ok := err.(*NativeKmsError); !ok {
			t.Fatalf("Encrypt() with status %d: error type = %T, want *NativeKmsError", status, err)
		}
		if library.wrapCallCount != 1 {
			t.Errorf("wrapCallCount = %d, want 1", library.wrapCallCount)
		}
	}
}

func TestNativeHkdfKeyWrapperV1_Decrypt_DelegatesToLibrary(t *testing.T) {
	library := newFakeKmsLibrary()
	library.unwrapPayloadToEmit = []byte{1, 2, 3, 4, 5}
	wrapper := newNativeHkdfKeyWrapperV1("service-a", library)

	wrapped := []byte{10, 20, 30, 40}
	result := make([]byte, 16)
	written, err := wrapper.Decrypt(wrapped, result)

	if err != nil {
		t.Fatalf("Decrypt() error = %v, want nil", err)
	}
	if written != 5 {
		t.Errorf("Decrypt() = %d, want 5", written)
	}
	if library.unwrapCallCount != 1 {
		t.Errorf("unwrapCallCount = %d, want 1", library.unwrapCallCount)
	}
	if library.lastService != "service-a" {
		t.Errorf("lastService = %q, want %q", library.lastService, "service-a")
	}
	if !bytes.Equal(library.lastUnwrapWrapped, wrapped) {
		t.Errorf("lastUnwrapWrapped = %v, want %v", library.lastUnwrapWrapped, wrapped)
	}
	if !bytes.Equal(result[:5], []byte{1, 2, 3, 4, 5}) {
		t.Errorf("result[:5] = %v, want [1 2 3 4 5]", result[:5])
	}
}

func TestNativeHkdfKeyWrapperV1_Decrypt_WhenLibraryFails_ReturnsNativeKmsError(t *testing.T) {
	for _, status := range []int32{-1, -2, -6} {
		library := newFakeKmsLibrary()
		library.unwrapDekStatus = status
		wrapper := newNativeHkdfKeyWrapperV1("service-d", library)

		_, err := wrapper.Decrypt([]byte{10, 20, 30}, make([]byte, 8))

		if _, ok := err.(*NativeKmsError); !ok {
			t.Fatalf("Decrypt() with status %d: error type = %T, want *NativeKmsError", status, err)
		}
		if library.unwrapCallCount != 1 {
			t.Errorf("unwrapCallCount = %d, want 1", library.unwrapCallCount)
		}
	}
}

func TestNativeHkdfKeyWrapperV1_GenerateAndWrap_DelegatesToLibrary(t *testing.T) {
	library := newFakeKmsLibrary()
	library.generateAndWrapPayloadToEmit = []byte{11, 22, 33, 44, 55}
	wrapper := newNativeHkdfKeyWrapperV1("service-e", library)

	result := make([]byte, 16)
	written, err := wrapper.GenerateAndWrap(result)

	if err != nil {
		t.Fatalf("GenerateAndWrap() error = %v, want nil", err)
	}
	if written != 5 {
		t.Errorf("GenerateAndWrap() = %d, want 5", written)
	}
	if library.generateAndWrapCallCount != 1 {
		t.Errorf("generateAndWrapCallCount = %d, want 1", library.generateAndWrapCallCount)
	}
	if library.lastService != "service-e" {
		t.Errorf("lastService = %q, want %q", library.lastService, "service-e")
	}
	if !bytes.Equal(result[:5], []byte{11, 22, 33, 44, 55}) {
		t.Errorf("result[:5] = %v, want [11 22 33 44 55]", result[:5])
	}
}

func TestNativeHkdfKeyWrapperV1_GenerateAndWrap_WhenLibraryFails_ReturnsNativeKmsError(t *testing.T) {
	for _, status := range []int32{-1, -3, -7} {
		library := newFakeKmsLibrary()
		library.generateAndWrapDekStatus = status
		wrapper := newNativeHkdfKeyWrapperV1("service-f", library)

		_, err := wrapper.GenerateAndWrap(make([]byte, 16))

		if _, ok := err.(*NativeKmsError); !ok {
			t.Fatalf("GenerateAndWrap() with status %d: error type = %T, want *NativeKmsError", status, err)
		}
		if library.generateAndWrapCallCount != 1 {
			t.Errorf("generateAndWrapCallCount = %d, want 1", library.generateAndWrapCallCount)
		}
	}
}
