package cli

import (
	myhash "cryptcore/internal/hash" // Алиас для твоего пакета
	"cryptcore/internal/mac"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"hash" // Стандартный интерфейс
	"io"
	"os"
)

// HMACCmd реализует подкоманду hmac
func HMACCmd(args []string) {
	fs := flag.NewFlagSet("hmac", flag.ExitOnError)
	algorithm := fs.String("algorithm", "sha256", "Hash algorithm: sha256 or sha512")
	input := fs.String("input", "", "Input file")
	key := fs.String("key", "", "Secret key (hex encoded or plain string)")

	fs.Parse(args)

	if *input == "" {
		fmt.Println("Error: --input is required")
		os.Exit(1)
	}
	if *key == "" {
		fmt.Println("Error: --key is required")
		os.Exit(1)
	}

	// Пробуем декодировать ключ как hex, если не вышло — берем как байты строки
	keyBytes, err := hex.DecodeString(*key)
	if err != nil {
		keyBytes = []byte(*key)
	}

	// Функция-конструктор, возвращающая hash.Hash
	var h func() hash.Hash

	switch *algorithm {
	case "sha256":
		// Используем адаптер, чтобы превратить твой *DigestSHA256 в hash.Hash
		h = func() hash.Hash { return myhash.NewSHA256() }
	case "sha512":
		h = sha512.New
	default:
		fmt.Printf("Error: unknown algorithm %s\n", *algorithm)
		os.Exit(1)
	}

	// Создаем HMAC
	hm := mac.New(h, keyBytes)

	// Открываем файл
	file, err := os.Open(*input)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Читаем и хешируем
	if _, err := io.Copy(hm, file); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Выводим результат
	fmt.Printf("%x  %s\n", hm.Sum(nil), *input)
}
