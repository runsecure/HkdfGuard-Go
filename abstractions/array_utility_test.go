package abstractions

import "testing"

func TestIsNullOrEmpty(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"all zero", make([]byte, 16), true},
		{"empty", []byte{}, true},
		{"nil", nil, true},
		{"non-zero byte", []byte{0, 0, 0, 1, 0}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNullOrEmpty(tt.input); got != tt.want {
				t.Errorf("IsNullOrEmpty(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestZeroMemory(t *testing.T) {
	t.Run("clears every byte", func(t *testing.T) {
		b := []byte{1, 2, 3, 4, 5}
		ZeroMemory(b)
		for i, v := range b {
			if v != 0 {
				t.Errorf("b[%d] = %d, want 0", i, v)
			}
		}
	})

	t.Run("empty slice does not panic", func(t *testing.T) {
		ZeroMemory([]byte{})
	})
}
