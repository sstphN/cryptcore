package main

import (
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

	// читаем входной файл как бинарь
	inputData, err := fs.ReadAll(opts.InputPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error reading input file:", err)
		os.Exit(1)
	}

	key, err := crypto.ParseHexKey(opts.KeyHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid key:", err)
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
		fmt.Fprintln(os.Stderr, "unsupported mode:", opts.Mode)
		os.Exit(1)
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
