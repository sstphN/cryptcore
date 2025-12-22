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
	IVHex      string
	UseIVFlag  bool
	Password   string
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
	password := fs.String("password", "", "Password for key derivation")

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
		Password:   *password,
	}

	// Валидация: Нельзя указывать и --key, и --password одновременно.
	if opts.KeyHex != "" && opts.Password != "" {
		return nil, fmt.Errorf("cannot use both --key and --password")
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
	if o.InputPath == "" {
		return errors.New("--input is required")
	}

	// Ключ обязателен только если нет пароля и мы расшифровываем (или если шифруем и не хотим генерить)
	// Для Decrypt нужен либо KeyHex, либо Password
	if o.Decrypt && o.KeyHex == "" && o.Password == "" {
		return errors.New("either --key or --password is mandatory for decryption")
	}

	// IV-логика
	if o.Mode == "ecb" && o.UseIVFlag {
		return errors.New("--iv is not allowed in ECB mode")
	}
	// При шифровании с паролем IV тоже генерируется, но это handled in main
	if o.Mode != "ecb" && o.Encrypt && o.UseIVFlag {
		return errors.New("--iv must not be provided in encryption mode; IV is generated automatically")
	}

	return nil
}
