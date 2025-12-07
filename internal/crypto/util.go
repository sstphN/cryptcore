package crypto

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

const BlockSize = aes.BlockSize // 16 bytes for AES-128

func ParseHexKey(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	if len(key) != 16 {
		return nil, errors.New("AES-128 key must be 16 bytes (32 hex chars)")
	}
	return key, nil
}

func ParseHexIV(hexIV string) ([]byte, error) {
	iv, err := hex.DecodeString(hexIV)
	if err != nil {
		return nil, err
	}
	if len(iv) != BlockSize {
		return nil, errors.New("IV must be 16 bytes (32 hex chars)")
	}
	return iv, nil
}

func GenerateRandomIV() ([]byte, error) {
	iv := make([]byte, BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return iv, nil
}

func xorBlocks(dst, a, b []byte) {
	for i := 0; i < len(a); i++ {
		dst[i] = a[i] ^ b[i]
	}
}
