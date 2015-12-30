// chacha20_amd64.go - AMD64 optimized chacha20.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to chacha20, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build amd64,!gccgo,!appengine
package chacha20

func blocksAmd64SSE2(sigma, one, x *uint32, in, out *byte, nrBlocks uint)

// One day these won't be parameters when PeachPy fixes issue #11, and they
// can be made into local data, though leaving them as is isn't horrible
// since the assembly code doesn't have XMM registers to spare.  Minor gain
// from being able to ensure they're 16 byte aligned.
var one = [4]uint32{1, 0, 0, 0}
var sigma = [4]uint32{sigma0, sigma1, sigma2, sigma3}

func blocksAmd64(x *[stateSize]uint32, in []byte, out []byte, nrBlocks int) {
	if in == nil {
		for i := range out {
			out[i] = 0
		}
		in = out
	}

	blocksAmd64SSE2(&sigma[0], &one[0], &x[0], &in[0], &out[0], uint(nrBlocks))
}

func init() {
	blocksFn = blocksAmd64
	usingVectors = true
}
