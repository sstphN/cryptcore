package hash

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"
)

func BenchmarkParallelSHA256(b *testing.B) {
	// Создаем "файл" в памяти размером 10 МБ
	size := 10 * 1024 * 1024
	data := make([]byte, size)
	rand.Read(data)
	reader := bytes.NewReader(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Seek(0, io.SeekStart)
		ParallelSHA256(reader)
	}
}

func BenchmarkSerialSHA256(b *testing.B) {
	size := 10 * 1024 * 1024
	data := make([]byte, size)
	rand.Read(data)
	reader := bytes.NewReader(data)
	hasher := sha256.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Seek(0, io.SeekStart)
		hasher.Reset()
		io.Copy(hasher, reader)
	}
}
