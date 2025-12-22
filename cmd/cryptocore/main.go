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
	"cryptcore/internal/kdf"
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
	case "derive":
		handleDerive(os.Args[2:])
	default:
		// backward compatibility: encryption/decryption через флаги
		if len(command) > 0 && command[0] == '-' {
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

	var hashBytes []byte

	if opts.Algorithm == "par-sha256" {
		hashBytes, err = myhash.ParallelSHA256(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error hashing file (parallel): %v\n", err)
			os.Exit(1)
		}
	} else {
		var hasher hash.Hash

		switch opts.Algorithm {
		case "sha256":
			hasher = myhash.NewSHA256()
		case "sha512":
			hasher = sha512.New()
		default:
			fmt.Fprintf(os.Stderr, "unsupported algorithm: %s\n", opts.Algorithm)
			os.Exit(1)
		}

		buf := make([]byte, 32*1024)
		if _, err := io.CopyBuffer(hasher, f, buf); err != nil {
			fmt.Fprintf(os.Stderr, "error hashing file: %v\n", err)
			os.Exit(1)
		}
		hashBytes = hasher.Sum(nil)
	}

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

// Sprint 7 (m7.html): cryptocore derive --password ... [--salt hex] [--iterations N] [--length L] --algorithm pbkdf2 [--output file]
// stdout: KEY_HEX SALT_HEX
func handleDerive(args []string) {
	opts, err := cli.ParseDeriveArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "derive error: %v\n", err)
		os.Exit(1)
	}

	// salt: либо задан, либо генерим 16 байт (как требует m7)
	var salt []byte
	if opts.SaltHex != "" {
		salt, err = hex.DecodeString(opts.SaltHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid salt hex: %v\n", err)
			os.Exit(1)
		}
	} else {
		salt, err = crypto.GenerateRandomBytes(16)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error generating salt: %v\n", err)
			os.Exit(1)
		}
	}

	// PBKDF2-HMAC-SHA256 (ваша реализация kdf.Key, sha256 = myhash.NewSHA256)
	pass := []byte(opts.Password)
	key := kdf.Key(func() hash.Hash { return myhash.NewSHA256() }, pass, salt, opts.Iterations, opts.Length)

	// should: очистить пароль из памяти
	for i := range pass {
		pass[i] = 0
	}

	// optional --output: писать raw bytes ключа
	if opts.OutputPath != "" {
		if err := fs.WriteAll(opts.OutputPath, key); err != nil {
			fmt.Fprintf(os.Stderr, "error writing key to file: %v\n", err)
			os.Exit(1)
		}
	}

	// stdout: KEY_HEX SALT_HEX
	fmt.Printf("%s  %s\n", hex.EncodeToString(key), hex.EncodeToString(salt))
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

	if opts.Password != "" {
		// PBKDF2-режим для шифрования/расшифрования (как у тебя было)
		if opts.Encrypt {
			salt, err = crypto.GenerateRandomBytes(16)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error generating salt:", err)
				os.Exit(1)
			}
			key = kdf.Key(func() hash.Hash { return myhash.NewSHA256() }, []byte(opts.Password), salt, 4096, 16)
			fmt.Printf("[INFO] Using PBKDF2 with generated salt: %x\n", salt)
		} else {
			if len(inputData) < 16 {
				fmt.Fprintln(os.Stderr, "error: input file too short to contain salt")
				os.Exit(1)
			}
			salt = inputData[:16]
			inputData = inputData[16:]

			key = kdf.Key(func() hash.Hash { return myhash.NewSHA256() }, []byte(opts.Password), salt, 4096, 16)
			fmt.Printf("[INFO] Using PBKDF2 with extracted salt: %x\n", salt)
		}
	} else {
		// raw key
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

	// если encrypt+password => соль в начало файла
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
	fmt.Println("  cryptocore <args>              # Encryption/Decryption")
	fmt.Println("  cryptocore dgst ...            # Hashing")
	fmt.Println("  cryptocore hmac ...            # HMAC")
	fmt.Println("  cryptocore derive ...          # Key derivation (PBKDF2)")
}
