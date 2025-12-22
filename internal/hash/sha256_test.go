package hash

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestSHA256(t *testing.T) {
	input := []byte("hello world")

	h := NewSHA256()
	h.Write(input)
	got := h.Sum(nil)

	// Эталонная реализация (Go standard library)
	stdH := sha256.New()
	stdH.Write(input)
	want := stdH.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Errorf("SHA256 mismatch:\ngot:  %x\nwant: %x", got, want)
	}
}

func TestSHA256_Empty(t *testing.T) {
	h := NewSHA256()
	got := h.Sum(nil)

	stdH := sha256.New()
	want := stdH.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Errorf("SHA256 empty mismatch:\ngot:  %x\nwant: %x", got, want)
	}
}

func TestSHA256_MultiWrite(t *testing.T) {
	h := NewSHA256()
	h.Write([]byte("hello"))
	h.Write([]byte(" "))
	h.Write([]byte("world"))
	got := h.Sum(nil)

	stdH := sha256.New()
	stdH.Write([]byte("hello world"))
	want := stdH.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Errorf("SHA256 multi-write mismatch:\ngot:  %x\nwant: %x", got, want)
	}
}
