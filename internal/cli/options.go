package cli

import (
	"errors"
	"flag"
	"fmt"
)

type Options struct {
	Algorithm  string
	Mode       string
	Encrypt    bool
	Decrypt    bool
	KeyHex     string
	InputPath  string
	OutputPath string

	// Sprint 2
	IVHex     string
	UseIVFlag bool
}

func ParseArgs(args []string) (*Options, error) {
	fs := flag.NewFlagSet("cryptocore", flag.ContinueOnError)

	algo := fs.String("algorithm", "", "cipher algorithm (must be aes)")
	mode := fs.String("mode", "", "mode of operation (ecb, cbc, cfb, ofb, ctr)")
	encrypt := fs.Bool("encrypt", false, "encrypt")
	decrypt := fs.Bool("decrypt", false, "decrypt")
	key := fs.String("key", "", "hex-encoded AES-128 key (16 bytes => 32 hex chars)")
	input := fs.String("input", "", "input file path")
	output := fs.String("output", "", "output file path")

	iv := fs.String("iv", "", "hex-encoded 16-byte IV (for decryption in CBC/CFB/OFB/CTR)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	opts := &Options{
		Algorithm:  *algo,
		Mode:       *mode,
		Encrypt:    *encrypt,
		Decrypt:    *decrypt,
		KeyHex:     *key,
		InputPath:  *input,
		OutputPath: *output,
		IVHex:      *iv,
		UseIVFlag:  *iv != "",
	}

	if err := validateOptions(opts); err != nil {
		return nil, err
	}

	return opts, nil
}

func validateOptions(o *Options) error {
	if o.Algorithm != "aes" {
		return errors.New("only --algorithm aes is supported")
	}
	if o.Mode == "" {
		return errors.New("--mode is required (ecb, cbc, cfb, ofb, ctr)")
	}

	if o.Encrypt == o.Decrypt {
		return errors.New("exactly one of --encrypt or --decrypt must be set")
	}

	if o.KeyHex == "" {
		return errors.New("--key is required")
	}
	if o.InputPath == "" {
		return errors.New("--input is required")
	}

	// ECB не использует IV
	if o.Mode == "ecb" && o.UseIVFlag {
		return errors.New("--iv is not allowed in ECB mode")
	}

	// Для режимов с IV: правила Sprint 2
	if o.Mode == "cbc" || o.Mode == "cfb" || o.Mode == "ofb" || o.Mode == "ctr" {
		if o.Encrypt && o.UseIVFlag {
			// по ТЗ можно либо игнорировать и варнить, либо считать ошибкой; делаем ошибку
			return errors.New("--iv must not be provided in encryption mode; IV is generated automatically")
		}
		// в режиме decrypt IV может быть либо в флаге, либо в файле (проверка длины hex — в crypto.ParseHexIV)
	}

	return nil
}

func (o *Options) String() string {
	return fmt.Sprintf("algorithm=%s mode=%s encrypt=%v decrypt=%v input=%s output=%s",
		o.Algorithm, o.Mode, o.Encrypt, o.Decrypt, o.InputPath, o.OutputPath)
}
