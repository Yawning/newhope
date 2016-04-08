// newhope.go - New Hope interface.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to newhope, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// Package newhope implements a key exchange based on the Ring Learning with
// Errors Problem.  It is a mechanical port of the Public Domain implementation
// by Erdem Alkim, Léo Ducas, Thomas Pöppelmann, and Peter Schwabe.
//
// For more information see: https://cryptojedi.org/papers/newhope-20151110.pdf
//
package newhope

import (
	"io"

	"golang.org/x/crypto/sha3"
)

const (
	// SharedSecretSize is the length of a Shared Secret in bytes.
	SharedSecretSize = 32

	// UpstreamVersion is the version of the upstream package this
	// implementation is compatible with.
	UpstreamVersion = "20160328"

	// RecBytes is the length of the reconciliation data in bytes.
	RecBytes = 256

	// SendASize is the length of Alice's public key in bytes.
	SendASize = PolyBytes + SeedBytes

	// SendBSize is the length of Bob's public key in bytes.
	SendBSize = PolyBytes + RecBytes
)

func encodeA(r []byte, pk *poly, seed *[SeedBytes]byte) {
	pk.toBytes(r)
	for i := 0; i < SeedBytes; i++ {
		r[PolyBytes+i] = seed[i]
	}
}

func decodeA(pk *poly, seed *[SeedBytes]byte, r []byte) {
	pk.fromBytes(r)
	for i := range seed {
		seed[i] = r[PolyBytes+i]
	}
}

func encodeB(r []byte, b *poly, c *poly) {
	b.toBytes(r)
	for i := 0; i < paramN/4; i++ {
		r[PolyBytes+i] = byte(c.coeffs[4*i]) | byte(c.coeffs[4*i+1]<<2) | byte(c.coeffs[4*i+2]<<4) | byte(c.coeffs[4*i+3]<<6)
	}
}

func decodeB(b *poly, c *poly, r []byte) {
	b.fromBytes(r)
	for i := 0; i < paramN/4; i++ {
		c.coeffs[4*i+0] = uint16(r[PolyBytes+i]) & 0x03
		c.coeffs[4*i+1] = uint16(r[PolyBytes+i]>>2) & 0x03
		c.coeffs[4*i+2] = uint16(r[PolyBytes+i]>>4) & 0x03
		c.coeffs[4*i+3] = uint16(r[PolyBytes+i] >> 6)
	}
}

func memwipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// PublicKeyAlice is Alice's New Hope public key.
type PublicKeyAlice struct {
	Send [SendASize]byte
}

// PrivateKeyAlice is Alice's New Hope private key.
type PrivateKeyAlice struct {
	sk poly
}

// GenerateKeyPair returns a private/public key pair.  The private key is
// generated using the given reader, which must return random data.  The
// receiver side of the key exchange (aka "Bob") MUST use KeyExchangeBob()
// instead of this routine.
func GenerateKeyPair(rand io.Reader) (*PrivateKeyAlice, *PublicKeyAlice, error) {
	var a, e, pk, r poly
	var seed, noiseSeed [SeedBytes]byte

	// seed <- Sample({0, 1}^256)
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, nil, err
	}
	// a <- Parse(SHAKE-128(seed))
	a.uniform(&seed)

	// s, e <- Sample(psi(n, 12))
	if _, err := io.ReadFull(rand, noiseSeed[:]); err != nil {
		return nil, nil, err
	}
	defer memwipe(noiseSeed[:])
	privKey := new(PrivateKeyAlice)
	privKey.sk.getNoise(&noiseSeed, 0)
	privKey.sk.ntt()
	e.getNoise(&noiseSeed, 1)
	e.ntt()

	// b <- as + e
	pubKey := new(PublicKeyAlice)
	r.pointwise(&privKey.sk, &a)
	pk.add(&e, &r)
	encodeA(pubKey.Send[:], &pk, &seed)

	return privKey, pubKey, nil
}

// PublicKeyBob is Bob's New Hope public key.
type PublicKeyBob struct {
	Send [SendBSize]byte
}

// KeyExchangeBob is the Responder side of the Ring-LWE key exchange.  The
// shared secret and "public key" (key + reconciliation data) are generated
// using the given reader, which must return random data.
func KeyExchangeBob(rand io.Reader, alicePk *PublicKeyAlice) (*PublicKeyBob, []byte, error) {
	var pka, a, sp, ep, u, v, epp, r poly
	var seed, noiseSeed [SeedBytes]byte

	if _, err := io.ReadFull(rand, noiseSeed[:]); err != nil {
		return nil, nil, err
	}
	defer memwipe(noiseSeed[:])

	// a <- Parse(SHAKE-128(seed))
	decodeA(&pka, &seed, alicePk.Send[:])
	a.uniform(&seed)

	// s', e', e'' <- Sample(psi(n, 12))
	sp.getNoise(&noiseSeed, 0)
	sp.ntt()
	ep.getNoise(&noiseSeed, 1)
	ep.ntt()
	epp.getNoise(&noiseSeed, 2)

	// u <- as' + e'
	u.pointwise(&a, &sp)
	u.add(&u, &ep)

	// v <- bs' + e''
	v.pointwise(&pka, &sp)
	v.invNtt()
	v.add(&v, &epp)

	// r <- Sample(HelpRec(v))
	r.helpRec(&v, &noiseSeed, 3)

	pubKey := new(PublicKeyBob)
	encodeB(pubKey.Send[:], &u, &r)

	// nu <- Rec(v, r)
	var nu [SharedSecretSize]byte
	rec(&nu, &v, &r)

	// mu <- SHA3-256(nu)
	mu := sha3.Sum256(nu[:])

	// Scrub the sensitive stuff...
	memwipe(nu[:])
	sp.reset()
	v.reset()

	return pubKey, mu[:], nil
}

// KeyExchangeAlice is the Initiaitor side of the Ring-LWE key exchange.  The
// provided private key is obliterated prior to returning, to promote
// implementing Perfect Forward Secrecy.
func KeyExchangeAlice(bobPk *PublicKeyBob, aliceSk *PrivateKeyAlice) ([]byte, error) {
	var u, r, vp poly

	decodeB(&u, &r, bobPk.Send[:])

	// v' <- us
	vp.pointwise(&aliceSk.sk, &u)
	vp.invNtt()

	// nu <- Rec(v', r)
	var nu [SharedSecretSize]byte
	rec(&nu, &vp, &r)

	// mu <- Sha3-256(nu)
	mu := sha3.Sum256(nu[:])

	// Scrub the sensitive stuff...
	memwipe(nu[:])
	vp.reset()
	aliceSk.sk.reset()

	return mu[:], nil
}
