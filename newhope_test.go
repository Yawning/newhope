// newhope_test.go - New Hope Integration tests.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to newhope, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package newhope

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func BenchmarkKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKeyPair(rand.Reader)
	}
}

func BenchmarkAlice(b *testing.B) {
	for i := 0; i < b.N; i++ {
		// Generate Alice's key's.
		alicePriv, alicePub, err := GenerateKeyPair(rand.Reader)
		if err != nil {
			b.Fatalf("GenerateKeyPair failed: %v", err)
		}

		// Finish Bob's handshake.
		b.StopTimer()
		bobPub, bobShared, err := KeyExchangeBob(rand.Reader, alicePub)
		if err != nil {
			b.Fatalf("KeyExchangeBob failed: %v", err)
		}
		b.StartTimer()

		// Finish Alice's handshake.
		aliceShared, err := KeyExchangeAlice(bobPub, alicePriv)
		if err != nil {
			b.Fatalf("KeyExchangeAlice failed: %v", err)
		}

		b.StopTimer()
		if !bytes.Equal(aliceShared, bobShared) {
			b.Fatalf("shared secrets mismatched")
		}
		b.StartTimer()
	}
}

func BenchmarkBob(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()

		// Generate Alice's key's.
		alicePriv, alicePub, err := GenerateKeyPair(rand.Reader)
		if err != nil {
			b.Fatalf("GenerateKeyPair failed: %v", err)
		}

		// Finish Bob's handshake.
		b.StartTimer()
		bobPub, bobShared, err := KeyExchangeBob(rand.Reader, alicePub)
		if err != nil {
			b.Fatalf("KeyExchangeBob failed: %v", err)
		}
		b.StopTimer()

		// Finish Alice's handshake.
		aliceShared, err := KeyExchangeAlice(bobPub, alicePriv)
		if err != nil {
			b.Fatalf("KeyExchangeAlice failed: %v", err)
		}

		if !bytes.Equal(aliceShared, bobShared) {
			b.Fatalf("shared secrets mismatched")
		}
	}
}

func TestIntegration(t *testing.T) {
	for i := 0; i < 1024; i++ {
		// Generate Alice's key's.
		alicePriv, alicePub, err := GenerateKeyPair(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKeyPair failed: %v", err)
		}

		// Finish Bob's handshake.
		bobPub, bobShared, err := KeyExchangeBob(rand.Reader, alicePub)
		if err != nil {
			t.Fatalf("KeyExchangeBob failed: %v", err)
		}

		// Finish Alice's handshake.
		aliceShared, err := KeyExchangeAlice(bobPub, alicePriv)
		if err != nil {
			t.Fatalf("KeyExchangeAlice failed: %v", err)
		}

		if !bytes.Equal(aliceShared, bobShared) {
			t.Fatalf("shared secrets mismatched")
		}

	}
}
