package hash

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSHA256(t *testing.T) {
	tests := []struct {
		input  string
		output string
	}{
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
	}

	for _, test := range tests {
		h := NewSHA256()
		_, _ = h.Write([]byte(test.input))
		hexSum := hex.EncodeToString(h.Sum(nil))

		if hexSum != test.output {
			t.Errorf("SHA256(%q) = %s; want %s", test.input, hexSum, test.output)
		}
	}
}

func TestSHA256_Reset(t *testing.T) {
	h := NewSHA256()
	_, _ = h.Write([]byte("abc"))
	h.Reset()
	_, _ = h.Write([]byte(""))
	hexSum := hex.EncodeToString(h.Sum(nil))
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hexSum != expected {
		t.Errorf("SHA256 after Reset = %s; want %s", hexSum, expected)
	}
}

func TestSHA256_LargeInput(t *testing.T) {
	input := bytes.Repeat([]byte("a"), 1000)
	expected := "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"

	h := NewSHA256()
	_, _ = h.Write(input)
	hexSum := hex.EncodeToString(h.Sum(nil))

	if hexSum != expected {
		t.Errorf("SHA256(1000 'a's) = %s; want %s", hexSum, expected)
	}
}
