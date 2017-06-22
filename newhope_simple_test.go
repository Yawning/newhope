// newhope_simple_test.go - NewHope-Simple Integration tests.
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

func testSimpleIntegration(t *testing.T) {
	for i := 0; i < 1024; i++ {
		// Generate Alice's key's.
		alicePriv, alicePub, err := GenerateKeyPairSimpleAlice(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKeyPairSimpleAlice failed: %v", err)
		}

		// Finish Bob's handshake.
		bobPub, bobShared, err := KeyExchangeSimpleBob(rand.Reader, alicePub)
		if err != nil {
			t.Fatalf("KeyExchangeSimpleBob failed: %v", err)
		}

		// Finish Alice's handshake.
		aliceShared, err := KeyExchangeSimpleAlice(bobPub, alicePriv)
		if err != nil {
			t.Fatalf("KeyExchangeSimpleAlice failed: %v", err)
		}

		if !bytes.Equal(aliceShared, bobShared) {
			t.Fatalf("shared secrets mismatched")
		}
	}
}

func TestSimpleIntegration(t *testing.T) {
	TorSampling = false
	testSimpleIntegration(t)
}

func TestSimpleIntegrationTor(t *testing.T) {
	TorSampling = true
	testSimpleIntegration(t)
}
