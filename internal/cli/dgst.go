package cli

import (
	"errors"
	"flag"
)

type DgstOptions struct {
	Algorithm  string
	InputPath  string
	OutputPath string
}

func ParseDgstArgs(args []string) (*DgstOptions, error) {
	fs := flag.NewFlagSet("dgst", flag.ContinueOnError)
	algo := fs.String("algorithm", "", "hash algorithm (sha256, sha512)")
	input := fs.String("input", "", "input file path")
	output := fs.String("output", "", "output file path (optional)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	opts := &DgstOptions{
		Algorithm:  *algo,
		InputPath:  *input,
		OutputPath: *output,
	}

	if err := validateDgstOptions(opts); err != nil {
		return nil, err
	}
	return opts, nil
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
