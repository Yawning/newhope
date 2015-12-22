// chacha20_amd64.go - AMD64 optimized chacha20.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to chacha20, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build amd64
package chacha20

func blocksAmd64SSE2(sigma, one, x *uint32, in, out *byte, nrBlocks uint)

func blocksAmd64(x *[stateSize]uint32, in []byte, out []byte, nrBlocks int) {
	// One day these won't be parameters when I'm not too retarded to figure
	// out more of the PeachPy syntax.
	one := [4]uint32{1, 0, 0, 0}
	sigma := [4]uint32{ sigma0, sigma1, sigma2, sigma3 }

	if in == nil {
		for i := range out {
			out[i] = 0
		}
		in = out
	}

	blocksAmd64SSE2(&sigma[0], &one[0], &x[0], &in[0], &out[0], uint(nrBlocks))

	// Stoping at 2^70 bytes per nonce is the user's responsibility.
	ctr := uint64(x[9])<<32 | uint64(x[8])
	ctr += uint64(nrBlocks)
	x[8] = uint32(ctr)
	x[9] = uint32(ctr >> 32)
}

func init() {
	blocksFn = blocksAmd64
	usingVectors = true
}
