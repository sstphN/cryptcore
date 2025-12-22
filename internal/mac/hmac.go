package mac

import (
	"hash"
)

type HMAC struct {
	opad, ipad   []byte
	outer, inner hash.Hash
}

func New(h func() hash.Hash, key []byte) hash.Hash {
	hm := &HMAC{
		outer: h(),
		inner: h(),
	}
	block := hm.inner.BlockSize()
	hm.ipad = make([]byte, block)
	hm.opad = make([]byte, block)

	if len(key) > block {
		// If key is too big, hash it.
		hm.outer.Write(key)
		key = hm.outer.Sum(nil)
	}
	copy(hm.ipad, key)
	copy(hm.opad, key)

	for i := range hm.ipad {
		hm.ipad[i] ^= 0x36
		hm.opad[i] ^= 0x5c
	}

	// Initialize inner hash
	hm.inner.Write(hm.ipad)
	return hm
}

func (h *HMAC) Sum(b []byte) []byte {
	origState := h.inner.Sum(nil)

	h.outer.Reset()
	h.outer.Write(h.opad)
	h.outer.Write(origState)
	return h.outer.Sum(b)
}

func (h *HMAC) Write(p []byte) (n int, err error) {
	return h.inner.Write(p)
}

func (h *HMAC) Size() int      { return h.outer.Size() }
func (h *HMAC) BlockSize() int { return h.outer.BlockSize() }
func (h *HMAC) Reset() {
	h.inner.Reset()
	h.inner.Write(h.ipad)
	// Outer reset is done in Sum, but clearing it here doesn't hurt
	h.outer.Reset()
}
