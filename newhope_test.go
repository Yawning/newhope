// newhope_test.go - NewHope Integration tests.
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

func testIntegration(t *testing.T) {
	for i := 0; i < 1024; i++ {
		// Generate Alice's key's.
		alicePriv, alicePub, err := GenerateKeyPairAlice(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKeyPairAlice failed: %v", err)
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

func TestIntegration(t *testing.T) {
	TorSampling = false
	testIntegration(t)
}

func TestIntegrationTor(t *testing.T) {
	TorSampling = true
	testIntegration(t)
}
