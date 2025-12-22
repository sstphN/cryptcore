package kdf

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestPBKDF2(t *testing.T) {
	// PBKDF2-HMAC-SHA256 test vectors
	password := []byte("password")
	salt := []byte("salt")
	keyLen := 32

	// Case 1: iter=1
	{
		iter := 1
		expected := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
		dk := Key(sha256.New, password, salt, iter, keyLen)
		if hex.EncodeToString(dk) != expected {
			t.Fatalf("Case 1 failed: got %s, want %s", hex.EncodeToString(dk), expected)
		}
	}

	// Case 2: iter=2
	{
		iter := 2
		expected := "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
		dk := Key(sha256.New, password, salt, iter, keyLen)
		if hex.EncodeToString(dk) != expected {
			t.Fatalf("Case 2 failed: got %s, want %s", hex.EncodeToString(dk), expected)
		}
	}
}
