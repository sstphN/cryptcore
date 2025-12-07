package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func ReadAll(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	return data, nil
}

func WriteAll(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	return nil
}

func DefaultEncryptedName(input string) string {
	return input + ".enc"
}

func DefaultDecryptedName(input string) string {
	base := filepath.Base(input)
	if strings.HasSuffix(base, ".enc") {
		return strings.TrimSuffix(input, ".enc") + ".dec"
	}
	return input + ".dec"
}
