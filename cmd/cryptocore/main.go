package main

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"

	"cryptcore/internal/cli"
	"cryptcore/internal/crypto"
	"cryptcore/internal/fs"
	myhash "cryptcore/internal/hash"
	"cryptcore/internal/kdf" // Новый импорт
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "dgst":
		handleDgst(os.Args[2:])
	case "hmac":
		cli.HMACCmd(os.Args[2:])
	default:
		if command[0] == '-' {
			handleEncryption(os.Args[1:])
		} else {
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
			printHelp()
			os.Exit(1)
		}
	}
}

func handleDgst(args []string) {
	opts, err := cli.ParseDgstArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dgst error: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Open(opts.InputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	var hasher io.Writer
	var sumCalc func() []byte

	if opts.Algorithm == "sha256" {
		h := myhash.NewSHA256()
		hasher = h
		sumCalc = func() []byte { return h.Sum(nil) }
	} else if opts.Algorithm == "sha512" {
		h := sha512.New()
		hasher = h
		sumCalc = func() []byte { return h.Sum(nil) }
	}

	buf := make([]byte, 32*1024)
	if _, err := io.CopyBuffer(hasher, f, buf); err != nil {
		fmt.Fprintf(os.Stderr, "error hashing file: %v\n", err)
		os.Exit(1)
	}

	hashBytes := sumCalc()
	hashStr := hex.EncodeToString(hashBytes)

	output := fmt.Sprintf("%s  %s\n", hashStr, opts.InputPath)

	if opts.OutputPath != "" {
		if err := fs.WriteAll(opts.OutputPath, []byte(output)); err != nil {
			fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Print(output)
	}
}

func handleEncryption(args []string) {
	opts, err := cli.ParseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	inputData, err := fs.ReadAll(opts.InputPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error reading input file:", err)
		os.Exit(1)
	}

	var key []byte
	var salt []byte

	// Логика работы с ключами и паролями
	if opts.Password != "" {
		// --- Режим работы с паролем (PBKDF2) ---
		if opts.Encrypt {
			// 1. Генерируем случайную соль (16 байт)
			salt, err = crypto.GenerateRandomBytes(16)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error generating salt:", err)
				os.Exit(1)
			}
			// 2. Генерируем ключ из пароля
			key = kdf.Key(func() hash.Hash { return myhash.NewSHA256() }, []byte(opts.Password), salt, 4096, 16)

			fmt.Printf("[INFO] Using PBKDF2 with generated salt: %x\n", salt)
		} else {
			// Decrypt
			// 1. Соль должна быть в начале файла (первые 16 байт)
			if len(inputData) < 16 {
				fmt.Fprintln(os.Stderr, "error: input file too short to contain salt")
				os.Exit(1)
			}
			salt = inputData[:16]
			inputData = inputData[16:] // Отрезаем соль, оставляем только шифротекст

			// 2. Восстанавливаем ключ
			key = kdf.Key(func() hash.Hash { return myhash.NewSHA256() }, []byte(opts.Password), salt, 4096, 16)

			fmt.Printf("[INFO] Using PBKDF2 with extracted salt: %x\n", salt)
		}
	} else {
		// --- Режим работы с raw-ключом (Sprint 1-3) ---
		var keyHex string
		if opts.Encrypt && opts.KeyHex == "" {
			newKey, err := crypto.GenerateRandomBytes(16)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error generating key:", err)
				os.Exit(1)
			}
			keyHex = hex.EncodeToString(newKey)
			fmt.Printf("[INFO] Generated random key: %s\n", keyHex)
		} else {
			keyHex = opts.KeyHex
		}

		key, err = crypto.ParseHexKey(keyHex)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid key:", err)
			os.Exit(1)
		}
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

	// Если шифровали с паролем, нужно добавить соль в начало файла
	if opts.Password != "" && opts.Encrypt {
		finalOutput := make([]byte, 0, len(salt)+len(outputData))
		finalOutput = append(finalOutput, salt...)
		finalOutput = append(finalOutput, outputData...)
		outputData = finalOutput
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

func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("  cryptocore <args>               # Encryption/Decryption")
	fmt.Println("  cryptocore dgst ...             # Hashing")
	fmt.Println("  cryptocore hmac ...             # HMAC")
}
