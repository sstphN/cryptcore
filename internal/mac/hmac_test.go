package mac

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestHMAC_SHA256_RFC4231_Case1(t *testing.T) {
	// RFC 4231 Test Case 1
	key := []byte{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b}
	data := []byte("Hi There")
	expected := "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

	h := New(sha256.New, key)
	h.Write(data)
	sum := h.Sum(nil)
	hexSum := hex.EncodeToString(sum)

	if hexSum != expected {
		t.Errorf("got %s, want %s", hexSum, expected)
	}
}
