package crypto

import (
	"crypto/aes"
	"errors"
	"fmt"
)

// EncryptWithIVMode: для CBC/CFB/OFB/CTR при шифровании.
// Формат файла: <16-байтный IV>iphertext>.
func EncryptWithIVMode(mode string, key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if block.BlockSize() != BlockSize {
		return nil, errors.New("unexpected AES block size")
	}

	iv, err := GenerateRandomIV()
	if err != nil {
		return nil, fmt.Errorf("cannot generate IV: %w", err)
	}

	var ciphertext []byte

	switch mode {
	case "cbc":
		ciphertext, err = encryptCBC(block, iv, plaintext)
	case "cfb":
		ciphertext, err = encryptCFB(block, iv, plaintext)
	case "ofb":
		ciphertext, err = encryptOFB(block, iv, plaintext)
	case "ctr":
		ciphertext, err = encryptCTR(block, iv, plaintext)
	default:
		return nil, errors.New("unsupported mode for IV encryption")
	}
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(iv)+len(ciphertext))
	out = append(out, iv...)
	out = append(out, ciphertext...)
	return out, nil
}

// DecryptWithIVMode: для CBC/CFB/OFB/CTR при расшифровании.
// Если useIVFlag = true, IV берётся из ivHex; иначе — первые 16 байт файла.
func DecryptWithIVMode(mode string, key, input []byte, ivHex string, useIVFlag bool) ([]byte, error) {
	if len(input) < BlockSize && !useIVFlag {
		return nil, errors.New("ciphertext file too short to contain IV")
	}

	var iv []byte
	var ciphertext []byte
	var err error

	if useIVFlag {
		iv, err = ParseHexIV(ivHex)
		if err != nil {
			return nil, err
		}
		ciphertext = input
	} else {
		iv = make([]byte, BlockSize)
		copy(iv, input[:BlockSize])
		ciphertext = input[BlockSize:]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	switch mode {
	case "cbc":
		return decryptCBC(block, iv, ciphertext)
	case "cfb":
		return decryptCFB(block, iv, ciphertext)
	case "ofb":
		return decryptOFB(block, iv, ciphertext)
	case "ctr":
		return decryptCTR(block, iv, ciphertext)
	default:
		return nil, errors.New("unsupported mode for IV decryption")
	}
}

// CBC (PKCS#7 required)
func encryptCBC(block cipherBlock, iv, plaintext []byte) ([]byte, error) {
	padded, err := PKCS7Pad(plaintext, BlockSize)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(padded))
	prev := make([]byte, BlockSize)
	copy(prev, iv)

	tmp := make([]byte, BlockSize)

	for bs := 0; bs < len(padded); bs += BlockSize {
		be := bs + BlockSize
		xorBlocks(tmp, padded[bs:be], prev)
		block.Encrypt(out[bs:be], tmp)
		copy(prev, out[bs:be])
	}
	return out, nil
}

func decryptCBC(block cipherBlock, iv, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%BlockSize != 0 {
		return nil, errors.New("ciphertext length must be multiple of block size for CBC")
	}
	out := make([]byte, len(ciphertext))
	prev := make([]byte, BlockSize)
	copy(prev, iv)

	tmp := make([]byte, BlockSize)

	for bs := 0; bs < len(ciphertext); bs += BlockSize {
		be := bs + BlockSize
		block.Decrypt(tmp, ciphertext[bs:be])
		xorBlocks(out[bs:be], tmp, prev)
		copy(prev, ciphertext[bs:be])
	}
	return PKCS7Unpad(out, BlockSize)
}

// CFB (stream, no padding)
func encryptCFB(block cipherBlock, iv, plaintext []byte) ([]byte, error) {
	out := make([]byte, len(plaintext))
	prev := make([]byte, BlockSize)
	copy(prev, iv)

	keystream := make([]byte, BlockSize)

	for i := 0; i < len(plaintext); {
		block.Encrypt(keystream, prev)
		n := BlockSize
		if len(plaintext)-i < BlockSize {
			n = len(plaintext) - i
		}
		for j := 0; j < n; j++ {
			out[i+j] = plaintext[i+j] ^ keystream[j]
		}
		copy(prev, prev[0:])
		copy(prev, out[i:i+n]) // shift = full block
		i += n
	}
	return out, nil
}

func decryptCFB(block cipherBlock, iv, ciphertext []byte) ([]byte, error) {
	out := make([]byte, len(ciphertext))
	prev := make([]byte, BlockSize)
	copy(prev, iv)

	keystream := make([]byte, BlockSize)

	for i := 0; i < len(ciphertext); {
		block.Encrypt(keystream, prev)
		n := BlockSize
		if len(ciphertext)-i < BlockSize {
			n = len(ciphertext) - i
		}
		for j := 0; j < n; j++ {
			out[i+j] = ciphertext[i+j] ^ keystream[j]
		}
		copy(prev, prev[0:])
		copy(prev, ciphertext[i:i+n])
		i += n
	}
	return out, nil
}

// OFB (stream, keystream independent of plaintext)
func encryptOFB(block cipherBlock, iv, plaintext []byte) ([]byte, error) {
	out := make([]byte, len(plaintext))
	stream := make([]byte, BlockSize)
	copy(stream, iv)

	keystream := make([]byte, BlockSize)

	for i := 0; i < len(plaintext); {
		block.Encrypt(keystream, stream)
		copy(stream, keystream)
		n := BlockSize
		if len(plaintext)-i < BlockSize {
			n = len(plaintext) - i
		}
		for j := 0; j < n; j++ {
			out[i+j] = plaintext[i+j] ^ keystream[j]
		}
		i += n
	}
	return out, nil
}

func decryptOFB(block cipherBlock, iv, ciphertext []byte) ([]byte, error) {
	// в OFB шифрование и расшифрование идентичны
	return encryptOFB(block, iv, ciphertext)
}

// CTR (stream, counter = IV + блоковый счётчик)
func encryptCTR(block cipherBlock, iv, plaintext []byte) ([]byte, error) {
	out := make([]byte, len(plaintext))
	counter := make([]byte, BlockSize)
	copy(counter, iv)

	keystream := make([]byte, BlockSize)

	for i := 0; i < len(plaintext); {
		block.Encrypt(keystream, counter)
		incrementCounter(counter)
		n := BlockSize
		if len(plaintext)-i < BlockSize {
			n = len(plaintext) - i
		}
		for j := 0; j < n; j++ {
			out[i+j] = plaintext[i+j] ^ keystream[j]
		}
		i += n
	}
	return out, nil
}

func decryptCTR(block cipherBlock, iv, ciphertext []byte) ([]byte, error) {
	// для CTR шифрование и расшифрование одинаковы
	return encryptCTR(block, iv, ciphertext)
}

type cipherBlock interface {
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}

func incrementCounter(c []byte) {
	for i := len(c) - 1; i >= 0; i-- {
		c[i]++
		if c[i] != 0 {
			break
		}
	}
}
