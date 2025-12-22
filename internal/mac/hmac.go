package mac

import (
	"hash"
)

type HMAC struct {
	opad  []byte
	ipad  []byte
	outer hash.Hash // внешний хеш
	inner hash.Hash // внутренний хеш
}

func New(h func() hash.Hash, key []byte) hash.Hash {
	hm := &HMAC{}
	hm.outer = h()
	hm.inner = h()
	blockSize := hm.inner.BlockSize()

	if len(key) > blockSize {
		// Используем временный хешер, чтобы не портить состояние inner/outer
		temp := h()
		temp.Write(key)
		key = temp.Sum(nil)
	}

	hm.ipad = make([]byte, blockSize)
	hm.opad = make([]byte, blockSize)
	copy(hm.ipad, key)
	copy(hm.opad, key)

	// 2. XOR с ipad (0x36) и opad (0x5c)
	for i := range hm.ipad {
		hm.ipad[i] ^= 0x36
		hm.opad[i] ^= 0x5c
	}

	hm.inner.Write(hm.ipad)

	return hm
}

func (h *HMAC) Write(p []byte) (n int, err error) {
	return h.inner.Write(p)
}

func (h *HMAC) Sum(b []byte) []byte {

	innerSum := h.inner.Sum(nil)

	h.outer.Reset()
	h.outer.Write(h.opad)

	h.outer.Write(innerSum)

	return h.outer.Sum(b)
}

func (h *HMAC) Reset() {
	h.inner.Reset()
	h.inner.Write(h.ipad)

	h.outer.Reset()

}

func (h *HMAC) Size() int {
	return h.outer.Size()
}

func (h *HMAC) BlockSize() int {
	return h.outer.BlockSize()
}
