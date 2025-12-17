package crypto

import (
	"crypto/rand"
	"fmt"
)

func GenerateRandomBytes(numBytes int) ([]byte, error) {
	if numBytes <= 0 {
		return nil, fmt.Errorf("number of bytes must be positive")
	}
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}
