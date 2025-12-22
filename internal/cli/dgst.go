package cli

import (
	"errors"
	"flag"
	"fmt"
)

type DgstOptions struct {
	Algorithm  string
	InputPath  string
	OutputPath string
}

func ParseDgstArgs(args []string) (*DgstOptions, error) {
	fs := flag.NewFlagSet("dgst", flag.ContinueOnError)
	algorithm := fs.String("algorithm", "sha256", "Hash algorithm (sha256, par-sha256, sha512)")
	input := fs.String("input", "", "Input file path")
	output := fs.String("output", "", "Output file path (optional)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if *input == "" {
		return nil, fmt.Errorf("input file is required")
	}

	if *algorithm != "sha256" && *algorithm != "sha512" && *algorithm != "par-sha256" {
		return nil, fmt.Errorf("unsupported algorithm: must be sha256, par-sha256 or sha512")
	}

	return &DgstOptions{
		Algorithm:  *algorithm,
		InputPath:  *input,
		OutputPath: *output,
	}, nil
}

func validateDgstOptions(o *DgstOptions) error {
	if o.Algorithm == "" {
		return errors.New("--algorithm is required (sha256, sha512)")
	}
	if o.Algorithm != "sha256" && o.Algorithm != "sha512" {
		return errors.New("unsupported algorithm: must be sha256 or sha512")
	}
	if o.InputPath == "" {
		return errors.New("--input is required")
	}
	return nil
}
