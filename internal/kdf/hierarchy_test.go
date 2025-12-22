package kdf

import (
	"bytes"
	"testing"
)

func TestDeriveKey_Deterministic(t *testing.T) {
	master := bytes.Repeat([]byte{0x00}, 32)

	k1 := DeriveKey(master, "encryption", 32)
	k2 := DeriveKey(master, "encryption", 32)

	if !bytes.Equal(k1, k2) {
		t.Fatalf("expected deterministic output, got different keys")
	}
}

func TestDeriveKey_ContextSeparation(t *testing.T) {
	master := bytes.Repeat([]byte{0x00}, 32)

	k1 := DeriveKey(master, "encryption", 32)
	k2 := DeriveKey(master, "authentication", 32)

	if bytes.Equal(k1, k2) {
		t.Fatalf("expected different keys for different contexts")
	}
}

func TestDeriveKey_Lengths(t *testing.T) {
	master := bytes.Repeat([]byte{0x11}, 32)

	for _, n := range []int{1, 16, 31, 32, 33, 64, 100} {
		k := DeriveKey(master, "ctx", n)
		if len(k) != n {
			t.Fatalf("length mismatch: got %d want %d", len(k), n)
		}
	}
}
