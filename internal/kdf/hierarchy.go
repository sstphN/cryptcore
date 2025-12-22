package kdf

import (
	myhash "cryptcore/internal/hash"
	"cryptcore/internal/mac"
	"encoding/binary"
	"hash"
)

func DeriveKey(masterKey []byte, context string, length int) []byte {
	if length <= 0 {
		return []byte{}
	}

	ctx := []byte(context)
	out := make([]byte, 0, length)

	var counter uint32 = 1
	for len(out) < length {
		ctr := make([]byte, 4)
		binary.BigEndian.PutUint32(ctr, counter)

		hm := mac.New(func() hash.Hash { return myhash.NewSHA256() }, masterKey)
		hm.Write(ctx)
		hm.Write(ctr)
		block := hm.Sum(nil)

		out = append(out, block...)
		counter++
	}

	return out[:length]
}
