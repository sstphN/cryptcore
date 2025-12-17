package main

import (
	"cryptcore/internal/crypto"
	"fmt"
)

func main() {
	key_set := make(map[string]struct{})
	num_keys := 1000

	for i := 0; i < num_keys; i++ {
		key, err := crypto.GenerateRandomBytes(16)
		if err != nil {
			panic(err)
		}
		if _, exists := key_set[string(key)]; exists {
			panic(fmt.Sprintf("Duplicate key found: %x", key))
		}
		key_set[string(key)] = struct{}{}
	}

	fmt.Printf("Successfully generated %d unique keys.\n", len(key_set))
}
