package cli

import (
	"encoding/hex"
	"flag"
	"fmt"
)

type DeriveOptions struct {
	Password   string
	SaltHex    string
	Iterations int
	Length     int
	Algorithm  string
	OutputPath string
}

func ParseDeriveArgs(args []string) (*DeriveOptions, error) {
	fs := flag.NewFlagSet("derive", flag.ContinueOnError)

	password := fs.String("password", "", "Password string")
	salt := fs.String("salt", "", "Salt as hex string (optional; if empty, random 16 bytes will be generated)")
	iterations := fs.Int("iterations", 100000, "Iteration count")
	length := fs.Int("length", 32, "Derived key length in bytes")
	algorithm := fs.String("algorithm", "pbkdf2", "KDF algorithm (pbkdf2)")
	output := fs.String("output", "", "Write derived key to file as raw bytes (optional)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if *password == "" {
		return nil, fmt.Errorf("password is required")
	}
	if *iterations <= 0 {
		return nil, fmt.Errorf("iterations must be > 0")
	}
	if *length <= 0 {
		return nil, fmt.Errorf("length must be > 0")
	}
	if *algorithm != "pbkdf2" {
		return nil, fmt.Errorf("unsupported algorithm: must be pbkdf2")
	}

	// Если salt задан — проверим, что это hex
	if *salt != "" {
		if _, err := hex.DecodeString(*salt); err != nil {
			return nil, fmt.Errorf("invalid salt hex: %v", err)
		}
	}

	return &DeriveOptions{
		Password:   *password,
		SaltHex:    *salt,
		Iterations: *iterations,
		Length:     *length,
		Algorithm:  *algorithm,
		OutputPath: *output,
	}, nil
}
