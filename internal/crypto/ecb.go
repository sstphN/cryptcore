package crypto

import (
	"crypto/aes"
	"errors"
)

func EncryptECB(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if block.BlockSize() != BlockSize {
		return nil, errors.New("unexpected AES block size")
	}

	padded, err := PKCS7Pad(plaintext, BlockSize)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(padded))
	for bs := 0; bs < len(padded); bs += BlockSize {
		be := bs + BlockSize
		block.Encrypt(out[bs:be], padded[bs:be])
	}
	return out, nil
}

func DecryptECB(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%BlockSize != 0 {
		return nil, errors.New("ciphertext length must be multiple of block size for ECB")
	}

	out := make([]byte, len(ciphertext))
	for bs := 0; bs < len(ciphertext); bs += BlockSize {
		be := bs + BlockSize
		block.Decrypt(out[bs:be], ciphertext[bs:be])
	}

	return PKCS7Unpad(out, BlockSize)
}
