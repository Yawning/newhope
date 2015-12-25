// poly.go - New Hope polynomial.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to newhope, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package newhope

import (
	"encoding/binary"

	"git.schwanenlied.me/yawning/newhope.git/chacha20"
	"golang.org/x/crypto/sha3"
)

const (
	// PolyBytes is the length of an encoded polynomial in bytes.
	PolyBytes = 2048

	shake128Rate = 168 // Stupid that this isn't exposed.
)

type poly struct {
	v [paramN]uint16
}

func (p *poly) reset() {
	for i := range p.v {
		p.v[i] = 0
	}
}

func (p *poly) fromBytes(a []byte) {
	for i := range p.v {
		p.v[i] = binary.LittleEndian.Uint16(a[2*i:]) & 0x3fff
	}
}

func (p *poly) toBytes(r []byte) {
	for i, v := range p.v {
		// Make sure that coefficients have only 14 bits.
		t := barrettReduce(v)
		m := t - paramQ
		c := int16(m)
		c >>= 15
		// Make sure that coefficients are in [0,q]
		t = m ^ ((t ^ m) & uint16(c))
		binary.LittleEndian.PutUint16(r[2*i:], t)
	}
}

func (p *poly) uniform(seed *[seedBytes]byte) {
	nBlocks := 16
	var buf [shake128Rate * 16]byte

	// h and buf are left unscrubbed because the output is public.
	h := sha3.NewShake128()
	h.Write(seed[:])
	h.Read(buf[:])

	for ctr, pos := 0, 0; ctr < paramN; {
		// Specialized for q = 12889.
		val := binary.LittleEndian.Uint16(buf[pos:]) & 0x3fff

		if val < paramQ {
			p.v[ctr] = val
			ctr++
		}
		pos += 2
		if pos > shake128Rate*nBlocks-2 {
			nBlocks = 1
			h.Read(buf[:shake128Rate])
			pos = 0
		}
	}
}

func (p *poly) getNoise(seed *[seedBytes]byte, nonce byte) {
	var buf [3 * paramN]byte
	var n [8]byte
	var v uint32
	var b [4]byte

	n[0] = nonce
	stream, err := chacha20.NewCipher(seed[:], n[:])
	if err != nil {
		panic(err)
	}
	stream.KeyStream(buf[:])
	stream.Reset()

	// First half of the output.
	for i := 0; i < paramN/2; i += 2 {
		v = 0
		jV := binary.LittleEndian.Uint32(buf[2*i:])
		for j := uint(0); j < 8; j++ {
			v += (jV >> j) & 0x01010101
		}
		jV = binary.LittleEndian.Uint32(buf[2*i+2*paramN:])
		for j := uint(0); j < 4; j++ {
			v += (jV >> j) & 0x01010101
		}
		binary.LittleEndian.PutUint32(b[0:], v)
		p.v[i] = paramQ + uint16(b[0]) - uint16(b[1])
		p.v[i+1] = paramQ + uint16(b[2]) - uint16(b[3])
	}

	// Second half of the output.
	for i := 0; i < paramN/2; i += 2 {
		v = 0
		jV := binary.LittleEndian.Uint32(buf[2*i+paramN:])
		for j := uint(0); j < 8; j++ {
			v += (jV >> j) & 0x01010101
		}
		jV = binary.LittleEndian.Uint32(buf[2*i+2*paramN:])
		for j := uint(0); j < 4; j++ {
			v += (jV >> (j + 4)) & 0x01010101
		}
		binary.LittleEndian.PutUint32(b[0:], v)
		p.v[i+paramN/2] = paramQ + uint16(b[0]) - uint16(b[1])
		p.v[i+paramN/2+1] = paramQ + uint16(b[2]) - uint16(b[3])
	}

	// Scrub the random bits...
	v = 0
	memwipe(b[:])
	memwipe(buf[:])
}

func (p *poly) pointwise(a, b *poly) {
	for i := range p.v {
		t := montgomeryReduce(3186 * uint32(b.v[i]))          // t is now in Montgomery domain
		p.v[i] = montgomeryReduce(uint32(a.v[i]) * uint32(t)) // p.v[i] is back in normal domain
	}
}

func (p *poly) add(a, b *poly) {
	for i := range p.v {
		p.v[i] = barrettReduce(a.v[i] + b.v[i])
	}
}

func (p *poly) ntt() {
	p.mulCoefficients(&psisBitrevMontgomery)
	ntt(&p.v, &omegasMontgomery)
}

func (p *poly) invNtt() {
	ntt(&p.v, &omegasInvMontgomery)
	p.mulCoefficients(&psisInvMontgomery)
}

func init() {
	if paramK != 12 {
		panic("poly.getNoise() only supports k=12")
	}
}
