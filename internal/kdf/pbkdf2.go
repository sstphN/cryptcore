package kdf

import (
	"cryptcore/internal/mac"
	"hash"
)

// Key derives a key from the password, salt and iteration count.
func Key(h func() hash.Hash, password []byte, salt []byte, iter int, keyLen int) []byte {
	prf := mac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var dk []byte
	U := make([]byte, hashLen)
	T := make([]byte, hashLen)
	block1 := make([]byte, 4)

	for block := 1; block <= numBlocks; block++ {
		// N.B.: The PRF Reset/Write calls are inlined here for performance in stdlib,
		// but we use our mac.HMAC methods.

		// 1. Initial U_1 = PRF(P, S || INT(i))
		prf.Reset()
		prf.Write(salt)
		block1[0] = byte(block >> 24)
		block1[1] = byte(block >> 16)
		block1[2] = byte(block >> 8)
		block1[3] = byte(block)
		prf.Write(block1)
		U = prf.Sum(U[:0])

		// T_i = U_1
		copy(T, U)

		// 2. Iterate
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = prf.Sum(U[:0])

			// T_i ^= U_n
			for x := range U {
				T[x] ^= U[x]
			}
		}

		dk = append(dk, T...)
	}

	return dk[:keyLen]
}
