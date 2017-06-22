// benchmark_test.go - NewHope benchmarks.
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

func benchGenerateKeyPairAlice(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKeyPairAlice(rand.Reader)
	}
}

func benchKeyExchangeAlice(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		// Generate Alice's key's.
		alicePriv, alicePub, err := GenerateKeyPairAlice(rand.Reader)
		if err != nil {
			b.Fatalf("GenerateKeyPairAlice failed: %v", err)
		}

		// Finish Bob's handshake.
		bobPub, bobShared, err := KeyExchangeBob(rand.Reader, alicePub)
		if err != nil {
			b.Fatalf("KeyExchangeBob failed: %v", err)
		}

		// Finish Alice's handshake.
		b.StartTimer()
		aliceShared, err := KeyExchangeAlice(bobPub, alicePriv)
		if err != nil {
			b.Fatalf("KeyExchangeAlice failed: %v", err)
		}
		b.StopTimer()

		// Sanity check.
		if !bytes.Equal(aliceShared, bobShared) {
			b.Fatalf("shared secrets mismatched")
		}
	}
}

func benchKeyExchangeBob(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		// Generate Alice's key's.
		alicePriv, alicePub, err := GenerateKeyPairAlice(rand.Reader)
		if err != nil {
			b.Fatalf("GenerateKeyPairAlice failed: %v", err)
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

		// Sanity check.
		if !bytes.Equal(aliceShared, bobShared) {
			b.Fatalf("shared secrets mismatched")
		}
	}
}

func BenchmarkNewHope(b *testing.B) {
	TorSampling = false
	b.Run("GenerateKeyPairAlice", benchGenerateKeyPairAlice)
	b.Run("KeyExchangeAlice", benchKeyExchangeAlice)
	b.Run("KeyExchangeBob", benchKeyExchangeBob)
}

func BenchmarkNewHopeTor(b *testing.B) {
	if testing.Short() {
		b.SkipNow()
	}
	TorSampling = true
	b.Run("GenerateKeyPairAlice", benchGenerateKeyPairAlice)
	b.Run("KeyExchangeAlice", benchKeyExchangeAlice)
	b.Run("KeyExchangeBob", benchKeyExchangeBob)
}

func benchGenerateKeyPairSimpleAlice(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKeyPairSimpleAlice(rand.Reader)
	}
}

func benchKeyExchangeSimpleAlice(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		// Generate Alice's key's.
		alicePriv, alicePub, err := GenerateKeyPairSimpleAlice(rand.Reader)
		if err != nil {
			b.Fatalf("GenerateKeyPairSimpleAlice failed: %v", err)
		}

		// Finish Bob's handshake.
		bobPub, bobShared, err := KeyExchangeSimpleBob(rand.Reader, alicePub)
		if err != nil {
			b.Fatalf("KeyExchangeSimpleBob failed: %v", err)
		}

		// Finish Alice's handshake.
		b.StartTimer()
		aliceShared, err := KeyExchangeSimpleAlice(bobPub, alicePriv)
		if err != nil {
			b.Fatalf("KeyExchangeSimpleAlice failed: %v", err)
		}
		b.StopTimer()

		// Sanity check.
		if !bytes.Equal(aliceShared, bobShared) {
			b.Fatalf("shared secrets mismatched")
		}
	}
}

func benchKeyExchangeSimpleBob(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		// Generate Alice's key's.
		alicePriv, alicePub, err := GenerateKeyPairSimpleAlice(rand.Reader)
		if err != nil {
			b.Fatalf("GenerateKeyPairSimpleAlice failed: %v", err)
		}

		// Finish Bob's handshake.
		b.StartTimer()
		bobPub, bobShared, err := KeyExchangeSimpleBob(rand.Reader, alicePub)
		if err != nil {
			b.Fatalf("KeyExchangeSimpleBob failed: %v", err)
		}
		b.StopTimer()

		// Finish Alice's handshake.
		aliceShared, err := KeyExchangeSimpleAlice(bobPub, alicePriv)
		if err != nil {
			b.Fatalf("KeyExchangeSimpleAlice failed: %v", err)
		}

		// Sanity check.
		if !bytes.Equal(aliceShared, bobShared) {
			b.Fatalf("shared secrets mismatched")
		}
	}
}

func BenchmarkNewHopeSimple(b *testing.B) {
	TorSampling = false
	b.Run("GenerateKeyPairSimpleAlice", benchGenerateKeyPairSimpleAlice)
	b.Run("KeyExchangeSimpleAlice", benchKeyExchangeSimpleAlice)
	b.Run("KeyExchangeSimpleBob", benchKeyExchangeSimpleBob)
}
