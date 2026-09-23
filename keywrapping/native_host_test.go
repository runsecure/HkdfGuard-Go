package keywrapping

import "testing"

// getLibrary calls the real newPlatformKmsLibrary, which calls purego.Dlopen/windows.LoadLibrary
// against a vendor-supplied native library this repo doesn't (and can't) bundle - so in this (or
// most CI) environments it returns an error rather than a library. That's fine: the only thing
// worth asserting here is that sync.OnceValues actually memoizes - both the value and the error -
// across calls, which holds regardless of which outcome the first call produced. Behavioral
// coverage of NativeHkdfKeyWrapperV1 itself lives in native_hkdf_key_wrapper_v1_test.go, against
// a fake kmsLibrary.
func TestGetLibrary_MemoizesAcrossCalls(t *testing.T) {
	library1, err1 := getLibrary()
	library2, err2 := getLibrary()

	if library1 != library2 {
		t.Errorf("getLibrary() returned different library values across calls: %v != %v", library1, library2)
	}
	if err1 != err2 {
		t.Errorf("getLibrary() returned different error values across calls: %v != %v", err1, err2)
	}
}
