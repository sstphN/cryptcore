package main

import (
	"cryptcore/internal/crypto"
	"fmt"
	"os"
)

func main() {
	// 10 MB file
	totalSize := 10 * 1024 * 1024
	f, err := os.Create("nist_test_data.bin")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	random_chunk, err := crypto.GenerateRandomBytes(totalSize)
	if err != nil {
		panic(err)
	}
	if _, err := f.Write(random_chunk); err != nil {
		panic(err)
	}

	fmt.Println("Generated nist_test_data.bin (10 MB)")
}
