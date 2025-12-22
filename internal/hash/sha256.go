package hash

import (
	"encoding/binary"
	"math/bits"
)

// K constants
var k = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// DigestSHA256 struct
type DigestSHA256 struct {
	h   [8]uint32
	x   [64]byte
	nx  int
	len uint64
}

func NewSHA256() *DigestSHA256 {
	d := &DigestSHA256{}
	d.Reset()
	return d
}

func (d *DigestSHA256) Reset() {
	d.h = [8]uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
	d.nx = 0
	d.len = 0
}

func (d *DigestSHA256) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	for _, c := range p {
		d.x[d.nx] = c
		d.nx++
		if d.nx == 64 {
			d.processBlock(d.x[:])
			d.nx = 0
		}
	}
	return nn, nil
}

func (d *DigestSHA256) Sum() []byte {
	d0 := *d
	hash := d0.checkSum()
	return hash[:]
}

func (d *DigestSHA256) checkSum() [32]byte {
	lenBits := d.len << 3
	d.x[d.nx] = 0x80
	for i := d.nx + 1; i < 64; i++ {
		d.x[i] = 0
	}
	if d.nx >= 56 {
		d.processBlock(d.x[:])
		for i := 0; i < 64; i++ {
			d.x[i] = 0
		}
	}
	binary.BigEndian.PutUint64(d.x[56:], lenBits)
	d.processBlock(d.x[:])

	var digest [32]byte
	binary.BigEndian.PutUint32(digest[0:], d.h[0])
	binary.BigEndian.PutUint32(digest[4:], d.h[1])
	binary.BigEndian.PutUint32(digest[8:], d.h[2])
	binary.BigEndian.PutUint32(digest[12:], d.h[3])
	binary.BigEndian.PutUint32(digest[16:], d.h[4])
	binary.BigEndian.PutUint32(digest[20:], d.h[5])
	binary.BigEndian.PutUint32(digest[24:], d.h[6])
	binary.BigEndian.PutUint32(digest[28:], d.h[7])
	return digest
}

func (d *DigestSHA256) processBlock(p []byte) {
	var w [64]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(p[i*4 : (i+1)*4])
	}
	for i := 16; i < 64; i++ {
		v0 := w[i-15]
		v1 := w[i-2]
		s0 := bits.RotateLeft32(v0, -7) ^ bits.RotateLeft32(v0, -18) ^ (v0 >> 3)
		s1 := bits.RotateLeft32(v1, -17) ^ bits.RotateLeft32(v1, -19) ^ (v1 >> 10)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}

	h0, h1, h2, h3, h4, h5, h6, h7 := d.h[0], d.h[1], d.h[2], d.h[3], d.h[4], d.h[5], d.h[6], d.h[7]

	for i := 0; i < 64; i++ {
		ch := (h4 & h5) ^ (^h4 & h6)
		maj := (h0 & h1) ^ (h0 & h2) ^ (h1 & h2)
		s0 := bits.RotateLeft32(h0, -2) ^ bits.RotateLeft32(h0, -13) ^ bits.RotateLeft32(h0, -22)
		s1 := bits.RotateLeft32(h4, -6) ^ bits.RotateLeft32(h4, -11) ^ bits.RotateLeft32(h4, -25)
		t1 := h7 + s1 + ch + k[i] + w[i]
		t2 := s0 + maj

		h7 = h6
		h6 = h5
		h5 = h4
		h4 = h3 + t1
		h3 = h2
		h2 = h1
		h1 = h0
		h0 = t1 + t2
	}

	d.h[0] += h0
	d.h[1] += h1
	d.h[2] += h2
	d.h[3] += h3
	d.h[4] += h4
	d.h[5] += h5
	d.h[6] += h6
	d.h[7] += h7
}
