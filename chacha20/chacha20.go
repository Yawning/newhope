// chacha20.go - A ChaCha stream cipher implementation.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to chacha20, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package chacha20

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"runtime"
)

const (
	// KeySize is the ChaCha20 key size in bytes.
	KeySize = 32

	// NonceSize is the ChaCha20 nonce size in bytes.
	NonceSize = 8

	// XNonceSize is the XChaCha20 nonce size in bytes.
	XNonceSize = 24

	// HNonceSize is the HChaCha20 nonce size in bytes.
	HNonceSize = 16

	// BlockSize is the ChaCha20 block size in bytes.
	BlockSize = 64

	stateSize    = 16 - 4
	chachaRounds = 20

	// The constant "expand 32-byte k" as little endian uint32s.
	sigma0 = uint32(0x61707865)
	sigma1 = uint32(0x3320646e)
	sigma2 = uint32(0x79622d32)
	sigma3 = uint32(0x6b206574)
)

var (
	// ErrInvalidKey is the error returned when the key is invalid.
	ErrInvalidKey = errors.New("key length must be KeySize bytes")

	// ErrInvalidNonce is the error returned when the nonce is invalid.
	ErrInvalidNonce = errors.New("nonce length must be NonceSize/XNonceSize bytes")

	useUnsafe    = false
	usingVectors = false
	blocksFn     = blocksRef
)

// A Cipher is an instance of ChaCha20/XChaCha20 using a particular key and
// nonce.
type Cipher struct {
	state [stateSize]uint32

	buf [BlockSize]byte
	off int
}

// Reset zeros the key data so that it will no longer appear in the process's
// memory.
func (c *Cipher) Reset() {
	for i := range c.state {
		c.state[i] = 0
	}
	for i := range c.buf {
		c.buf[i] = 0
	}
}

// XORKeyStream sets dst to the result of XORing src with the key stream.  Dst
// and src may be the same slice but otherwise should not overlap.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		src = src[:len(dst)]
	}

	for remaining := len(src); remaining > 0; {
		// Process multiple blocks at once.
		if c.off == BlockSize {
			nrBlocks := remaining / BlockSize
			directBytes := nrBlocks * BlockSize
			if nrBlocks > 0 {
				blocksFn(&c.state, src, dst, nrBlocks)
				remaining -= directBytes
				if remaining == 0 {
					return
				}
				dst = dst[directBytes:]
				src = src[directBytes:]
			}

			// If there's a partial block, generate 1 block of keystream into
			// the internal buffer.
			blocksFn(&c.state, nil, c.buf[:], 1)
			c.off = 0
		}

		// Process partial blocks from the buffered keystream.
		toXor := BlockSize - c.off
		if remaining < toXor {
			toXor = remaining
		}
		if toXor > 0 {
			for i, v := range src[:toXor] {
				dst[i] = v ^ c.buf[c.off+i]
			}
			dst = dst[toXor:]
			src = src[toXor:]

			remaining -= toXor
			c.off += toXor
		}
	}
}

// KeyStream sets dst to the raw keystream.
func (c *Cipher) KeyStream(dst []byte) {
	for remaining := len(dst); remaining > 0; {
		// Process multiple blocks at once.
		if c.off == BlockSize {
			nrBlocks := remaining / BlockSize
			directBytes := nrBlocks * BlockSize
			if nrBlocks > 0 {
				blocksFn(&c.state, nil, dst, nrBlocks)
				remaining -= directBytes
				if remaining == 0 {
					return
				}
				dst = dst[directBytes:]
			}

			// If there's a partial block, generate 1 block of keystream into
			// the internal buffer.
			blocksFn(&c.state, nil, c.buf[:], 1)
			c.off = 0
		}

		// Process partial blocks from the buffered keystream.
		toCopy := BlockSize - c.off
		if remaining < toCopy {
			toCopy = remaining
		}
		if toCopy > 0 {
			copy(dst[:toCopy], c.buf[c.off:c.off+toCopy])
			dst = dst[toCopy:]
			remaining -= toCopy
			c.off += toCopy
		}
	}
}

// ReKey reinitializes the ChaCha20/XChaCha20 instance with the provided key
// and nonce.
func (c *Cipher) ReKey(key, nonce []byte) error {
	if len(key) != KeySize {
		return ErrInvalidKey
	}

	switch len(nonce) {
	case NonceSize:
	case XNonceSize:
		var subkey [KeySize]byte
		var subnonce [HNonceSize]byte
		copy(subnonce[:], nonce[0:16])
		HChaCha(key, &subnonce, &subkey)
		key = subkey[:]
		nonce = nonce[16:24]
		defer func() {
			for i := range subkey {
				subkey[i] = 0
			}
		}()
	default:
		return ErrInvalidNonce
	}

	c.Reset()
	c.state[0] = binary.LittleEndian.Uint32(key[0:4])
	c.state[1] = binary.LittleEndian.Uint32(key[4:8])
	c.state[2] = binary.LittleEndian.Uint32(key[8:12])
	c.state[3] = binary.LittleEndian.Uint32(key[12:16])
	c.state[4] = binary.LittleEndian.Uint32(key[16:20])
	c.state[5] = binary.LittleEndian.Uint32(key[20:24])
	c.state[6] = binary.LittleEndian.Uint32(key[24:28])
	c.state[7] = binary.LittleEndian.Uint32(key[28:32])
	c.state[8] = 0
	c.state[9] = 0
	c.state[10] = binary.LittleEndian.Uint32(nonce[0:4])
	c.state[11] = binary.LittleEndian.Uint32(nonce[4:8])
	c.off = BlockSize
	return nil

}

// NewCipher returns a new ChaCha20/XChaCha20 instance.
func NewCipher(key, nonce []byte) (*Cipher, error) {
	c := new(Cipher)
	if err := c.ReKey(key, nonce); err != nil {
		return nil, err
	}
	return c, nil
}

// HChaCha is the HChaCha20 hash function used to make XChaCha.
func HChaCha(key []byte, nonce *[HNonceSize]byte, out *[32]byte) {
	var x [stateSize]uint32
	x[0] = binary.LittleEndian.Uint32(key[0:4])
	x[1] = binary.LittleEndian.Uint32(key[4:8])
	x[2] = binary.LittleEndian.Uint32(key[8:12])
	x[3] = binary.LittleEndian.Uint32(key[12:16])
	x[4] = binary.LittleEndian.Uint32(key[16:20])
	x[5] = binary.LittleEndian.Uint32(key[20:24])
	x[6] = binary.LittleEndian.Uint32(key[24:28])
	x[7] = binary.LittleEndian.Uint32(key[28:32])
	x[8] = binary.LittleEndian.Uint32(nonce[0:4])
	x[9] = binary.LittleEndian.Uint32(nonce[4:8])
	x[10] = binary.LittleEndian.Uint32(nonce[8:12])
	x[11] = binary.LittleEndian.Uint32(nonce[12:16])
	hChaChaRef(&x, out)
}

func hChaChaRef(x *[stateSize]uint32, out *[32]byte) {
	x0, x1, x2, x3 := sigma0, sigma1, sigma2, sigma3
	x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 := x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11]

	for i := chachaRounds; i > 0; i -= 2 {
		// quarterround(x, 0, 4, 8, 12)
		x0 += x4
		x12 ^= x0
		x12 = (x12 << 16) | (x12 >> 16)
		x8 += x12
		x4 ^= x8
		x4 = (x4 << 12) | (x4 >> 20)
		x0 += x4
		x12 ^= x0
		x12 = (x12 << 8) | (x12 >> 24)
		x8 += x12
		x4 ^= x8
		x4 = (x4 << 7) | (x4 >> 25)

		// quarterround(x, 1, 5, 9, 13)
		x1 += x5
		x13 ^= x1
		x13 = (x13 << 16) | (x13 >> 16)
		x9 += x13
		x5 ^= x9
		x5 = (x5 << 12) | (x5 >> 20)
		x1 += x5
		x13 ^= x1
		x13 = (x13 << 8) | (x13 >> 24)
		x9 += x13
		x5 ^= x9
		x5 = (x5 << 7) | (x5 >> 25)

		// quarterround(x, 2, 6, 10, 14)
		x2 += x6
		x14 ^= x2
		x14 = (x14 << 16) | (x14 >> 16)
		x10 += x14
		x6 ^= x10
		x6 = (x6 << 12) | (x6 >> 20)
		x2 += x6
		x14 ^= x2
		x14 = (x14 << 8) | (x14 >> 24)
		x10 += x14
		x6 ^= x10
		x6 = (x6 << 7) | (x6 >> 25)

		// quarterround(x, 3, 7, 11, 15)
		x3 += x7
		x15 ^= x3
		x15 = (x15 << 16) | (x15 >> 16)
		x11 += x15
		x7 ^= x11
		x7 = (x7 << 12) | (x7 >> 20)
		x3 += x7
		x15 ^= x3
		x15 = (x15 << 8) | (x15 >> 24)
		x11 += x15
		x7 ^= x11
		x7 = (x7 << 7) | (x7 >> 25)

		// quarterround(x, 0, 5, 10, 15)
		x0 += x5
		x15 ^= x0
		x15 = (x15 << 16) | (x15 >> 16)
		x10 += x15
		x5 ^= x10
		x5 = (x5 << 12) | (x5 >> 20)
		x0 += x5
		x15 ^= x0
		x15 = (x15 << 8) | (x15 >> 24)
		x10 += x15
		x5 ^= x10
		x5 = (x5 << 7) | (x5 >> 25)

		// quarterround(x, 1, 6, 11, 12)
		x1 += x6
		x12 ^= x1
		x12 = (x12 << 16) | (x12 >> 16)
		x11 += x12
		x6 ^= x11
		x6 = (x6 << 12) | (x6 >> 20)
		x1 += x6
		x12 ^= x1
		x12 = (x12 << 8) | (x12 >> 24)
		x11 += x12
		x6 ^= x11
		x6 = (x6 << 7) | (x6 >> 25)

		// quarterround(x, 2, 7, 8, 13)
		x2 += x7
		x13 ^= x2
		x13 = (x13 << 16) | (x13 >> 16)
		x8 += x13
		x7 ^= x8
		x7 = (x7 << 12) | (x7 >> 20)
		x2 += x7
		x13 ^= x2
		x13 = (x13 << 8) | (x13 >> 24)
		x8 += x13
		x7 ^= x8
		x7 = (x7 << 7) | (x7 >> 25)

		// quarterround(x, 3, 4, 9, 14)
		x3 += x4
		x14 ^= x3
		x14 = (x14 << 16) | (x14 >> 16)
		x9 += x14
		x4 ^= x9
		x4 = (x4 << 12) | (x4 >> 20)
		x3 += x4
		x14 ^= x3
		x14 = (x14 << 8) | (x14 >> 24)
		x9 += x14
		x4 ^= x9
		x4 = (x4 << 7) | (x4 >> 25)
	}

	// HChaCha returns x0...x3 | x12...x15, which corresponds to the
	// indexes of the ChaCha constant and the indexes of the IV.
	binary.LittleEndian.PutUint32(out[0:4], x0)
	binary.LittleEndian.PutUint32(out[4:8], x1)
	binary.LittleEndian.PutUint32(out[8:12], x2)
	binary.LittleEndian.PutUint32(out[12:16], x3)
	binary.LittleEndian.PutUint32(out[16:20], x12)
	binary.LittleEndian.PutUint32(out[20:24], x13)
	binary.LittleEndian.PutUint32(out[24:28], x14)
	binary.LittleEndian.PutUint32(out[28:32], x15)
	return
}

func init() {
	switch runtime.GOARCH {
	case "386", "amd64":
		// Abuse unsafe to skip calling binary.LittleEndian.PutUint32
		// in the critical path.  This is a big boost on systems that are
		// little endian and not overly picky about alignment.
		useUnsafe = true
	}
}

var _ cipher.Stream = (*Cipher)(nil)
