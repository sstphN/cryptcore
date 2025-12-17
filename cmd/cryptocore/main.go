package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"cryptcore/internal/cli"
	"cryptcore/internal/crypto"
	"cryptcore/internal/fs"
)

func main() {
	opts, err := cli.ParseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	var key []byte
	var keyHex string

	// Sprint 3: Генерация ключа, если он не предоставлен при шифровании
	if opts.Encrypt && opts.KeyHex == "" {
		newKey, err := crypto.GenerateRandomBytes(16)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error generating key:", err)
			os.Exit(1)
		}
		key = newKey
		keyHex = hex.EncodeToString(newKey)
		// Печать ключа в stdout, как требует KEY-2
		fmt.Printf("[INFO] Generated random key: %s\n", keyHex)
	} else {
		keyHex = opts.KeyHex
	}

	// Парсинг ключа (либо пользовательского, либо сгенерированного)
	key, err = crypto.ParseHexKey(keyHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid key:", err)
		os.Exit(1)
	}

	inputData, err := fs.ReadAll(opts.InputPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error reading input file:", err)
		os.Exit(1)
	}

	var outputData []byte
	switch opts.Mode {
	case "ecb":
		if opts.Encrypt {
			outputData, err = crypto.EncryptECB(key, inputData)
		} else {
			outputData, err = crypto.DecryptECB(key, inputData)
		}
	case "cbc", "cfb", "ofb", "ctr":
		if opts.Encrypt {
			outputData, err = crypto.EncryptWithIVMode(opts.Mode, key, inputData)
		} else {
			outputData, err = crypto.DecryptWithIVMode(opts.Mode, key, inputData, opts.IVHex, opts.UseIVFlag)
		}
	default:
		err = fmt.Errorf("unsupported mode: %s", opts.Mode)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "crypto error:", err)
		os.Exit(1)
	}

	outputPath := opts.OutputPath
	if outputPath == "" {
		if opts.Encrypt {
			outputPath = fs.DefaultEncryptedName(opts.InputPath)
		} else {
			outputPath = fs.DefaultDecryptedName(opts.InputPath)
		}
	}

	if err := fs.WriteAll(outputPath, outputData); err != nil {
		fmt.Fprintln(os.Stderr, "error writing output file:", err)
		os.Exit(1)
	}
}
