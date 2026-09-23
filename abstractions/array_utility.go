package abstractions

// IsNullOrEmpty reports whether input is empty or consists entirely of zero bytes.
func IsNullOrEmpty(input []byte) bool {
	for _, b := range input {
		if b != 0 {
			return false
		}
	}
	return true
}

// ZeroMemory overwrites every byte of input with zero.
func ZeroMemory(input []byte) {
	for i := range input {
		input[i] = 0
	}
}
