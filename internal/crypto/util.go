package crypto

import (
	"crypto/aes"
	"encoding/hex"
	"errors"
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

// GenerateRandomIV теперь использует наш новый модуль CSPRNG
func GenerateRandomIV() ([]byte, error) {
	return GenerateRandomBytes(BlockSize)
}

func xorBlocks(dst, a, b []byte) {
	for i := 0; i < len(a); i++ {
		dst[i] = a[i] ^ b[i]
	}
}
