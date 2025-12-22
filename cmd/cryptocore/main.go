package main

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"cryptcore/internal/cli"
	"cryptcore/internal/crypto"
	"cryptcore/internal/fs"
	myhash "cryptcore/internal/hash" // Наш пакет с SHA-256
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
	default:
		// Если команда не "dgst", считаем, что это старый режим шифрования (Sprint 1-3)
		// Но так как флаги парсятся пакетом flag, который ожидает аргументы,
		// нужно проверить, не начинается ли команда с тире (флага).
		// Если первый аргумент это флаг (например --algorithm), значит это режим шифрования.
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
		// Используем НАШУ реализацию с нуля
		h := myhash.NewSHA256()
		hasher = h
		sumCalc = h.Sum
	} else if opts.Algorithm == "sha512" {
		// Используем стандартную библиотеку как второй алгоритм
		h := sha512.New()
		hasher = h
		sumCalc = func() []byte { return h.Sum(nil) }
	}

	// Читаем файл кусками (chunked processing)
	buf := make([]byte, 32*1024) // 32KB buffer
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
	// Вставь сюда ВЕСЬ код из main() спринта 3
	// (начиная с opts, err := cli.ParseArgs(args) и до конца)
	// Для краткости я не дублирую его здесь, но ты должен перенести тело старого main сюда.

	opts, err := cli.ParseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	var key []byte
	var keyHex string

	if opts.Encrypt && opts.KeyHex == "" {
		newKey, err := crypto.GenerateRandomBytes(16)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error generating key:", err)
			os.Exit(1)
		}
		key = newKey
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

func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("  cryptocore <args>               # Encryption/Decryption (Sprint 1-3)")
	fmt.Println("  cryptocore dgst --algorithm <algo> --input <file> # Hashing (Sprint 4)")
}
