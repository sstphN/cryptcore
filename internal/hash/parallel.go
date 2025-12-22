package hash

import (
	"crypto/sha256"
	"fmt"
	"io"
	"runtime"
	"sync"
)

const ChunkSize = 1 * 1024 * 1024 // 1MB

type chunkJob struct {
	index int
	data  []byte
}

type chunkResult struct {
	index int
	sum   [32]byte
}

func ParallelSHA256(r io.Reader) ([]byte, error) {
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan chunkJob, workers*2)
	results := make(chan chunkResult, workers*2)

	var wg sync.WaitGroup
	wg.Add(workers)

	// Workers
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for job := range jobs {
				results <- chunkResult{
					index: job.index,
					sum:   sha256.Sum256(job.data),
				}
			}
		}()
	}

	// Close results when workers done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Producer: read file and push jobs
	chunks := 0
	for {
		buf := make([]byte, ChunkSize)
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])

			jobs <- chunkJob{index: chunks, data: data}
			chunks++
		}

		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			close(jobs)
			return nil, err
		}
	}
	close(jobs)

	if chunks == 0 {
		// Hash of empty input (совместимо с идеей “SHA256(concat(chunk_hashes))”)
		h := sha256.New()
		return h.Sum(nil), nil
	}

	// Collect results (order matters)
	hashes := make([][32]byte, chunks)
	got := 0
	for res := range results {
		if res.index < 0 || res.index >= chunks {
			return nil, fmt.Errorf("invalid chunk index: %d", res.index)
		}
		hashes[res.index] = res.sum
		got++
	}

	if got != chunks {
		return nil, fmt.Errorf("missing results: got %d, want %d", got, chunks)
	}

	// Final = SHA256( hash(chunk1) || hash(chunk2) || ... )
	final := sha256.New()
	for i := 0; i < chunks; i++ {
		final.Write(hashes[i][:])
	}
	return final.Sum(nil), nil
}
