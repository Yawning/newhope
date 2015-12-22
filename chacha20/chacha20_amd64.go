// chacha20_amd64.go - AMD64 optimized chacha20.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to chacha20, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build cgo, amd64
package chacha20

//
// /* If it isn't blatantly obvious, this is Ted Krovetz's Public Domain
//  * vec128 implementation from SUPERCOP, with some minor modifications.
//  *
//  *  * Everything non-SSE2 is removed, because I can't be bothered to deal
//  *    with runtime CPU feature dectection, and AMD64 by definition has
//  *    SSE2 support.
//  *  * _mm_loadu_si128/_mm_storeu_si128 are used so this can handle
//  *    everything not being 16 byte aligned at a minor performance penalty.
//  */
//
// #cgo CFLAGS: -O3
//
// #include <stdint.h>
// #include <stddef.h>
// #include <emmintrin.h>
//
// #define CHACHA_RNDS 20    /* 8 (high speed), 20 (conservative), 12 (middle) */
//
// typedef unsigned vec __attribute__ ((vector_size (16)));
//
// #define VBPI      3
//
// #define ONE       (vec)_mm_set_epi32(0,0,0,1)
// #define ROTV1(x)  (vec)_mm_shuffle_epi32((__m128i)x,_MM_SHUFFLE(0,3,2,1))
// #define ROTV2(x)  (vec)_mm_shuffle_epi32((__m128i)x,_MM_SHUFFLE(1,0,3,2))
// #define ROTV3(x)  (vec)_mm_shuffle_epi32((__m128i)x,_MM_SHUFFLE(2,1,0,3))
// #define ROTW7(x)  (vec)(_mm_slli_epi32((__m128i)x, 7) ^ _mm_srli_epi32((__m128i)x,25))
// #define ROTW12(x) (vec)(_mm_slli_epi32((__m128i)x,12) ^ _mm_srli_epi32((__m128i)x,20))
//
// #define ROTW8(x)  (vec)(_mm_slli_epi32((__m128i)x, 8) ^ _mm_srli_epi32((__m128i)x,24))
// #define ROTW16(x) (vec)(_mm_slli_epi32((__m128i)x,16) ^ _mm_srli_epi32((__m128i)x,16))
//
// #define DQROUND_VECTORS(a,b,c,d)                \
//     a += b; d ^= a; d = ROTW16(d);              \
//     c += d; b ^= c; b = ROTW12(b);              \
//     a += b; d ^= a; d = ROTW8(d);               \
//     c += d; b ^= c; b = ROTW7(b);               \
//     b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);  \
//     a += b; d ^= a; d = ROTW16(d);              \
//     c += d; b ^= c; b = ROTW12(b);              \
//     a += b; d ^= a; d = ROTW8(d);               \
//     c += d; b ^= c; b = ROTW7(b);               \
//     b = ROTV3(b); c = ROTV2(c); d = ROTV1(d);
//
// #define WRITE_XOR(in, op, d, v0, v1, v2, v3)                   \
//     _mm_storeu_si128((__m128i*)(op + d + 0), _mm_loadu_si128((__m128i*)(in + d + 0)) ^ (__m128i)(v0));   \
//     _mm_storeu_si128((__m128i*)(op + d + 4), _mm_loadu_si128((__m128i*)(in + d + 4)) ^ (__m128i)(v1));   \
//     _mm_storeu_si128((__m128i*)(op + d + 8), _mm_loadu_si128((__m128i*)(in + d + 8)) ^ (__m128i)(v2));   \
//     _mm_storeu_si128((__m128i*)(op + d + 12), _mm_loadu_si128((__m128i*)(in + d + 12)) ^ (__m128i)(v3)); \
//
// void
// chacha_blocksAmd64(const uint32_t *state, const uint8_t *in, uint8_t *out, size_t n)
// {
//   const uint32_t *ip = (const uint32_t *)(in);
//   uint32_t *op = (uint32_t *)(out);
//   __attribute__ ((aligned (16))) const unsigned chacha_const[] =
//                                {0x61707865,0x3320646E,0x79622D32,0x6B206574};
//   vec s0 = (vec)_mm_loadu_si128((__m128i*)(chacha_const));
//   vec s1 = (vec)_mm_loadu_si128((__m128i*)(state));
//   vec s2 = (vec)_mm_loadu_si128((__m128i*)(state + 4));
//   vec s3 = (vec)_mm_loadu_si128((__m128i*)(state + 8));
//
//   size_t nr_vec = n / VBPI; /* Number of parallel dispatches */
//   size_t nr_ser = n % VBPI; /* Remaining serially computed blocks */
//   for (size_t iters = 0; iters < nr_vec; iters++) {
//     vec v0,v1,v2,v3,v4,v5,v6,v7;
//     v4 = v0 = s0; v5 = v1 = s1; v6 = v2 = s2; v3 = s3;
//     v7 = v3 + ONE;
//     vec v8,v9,v10,v11;
//     v8 = v4; v9 = v5; v10 = v6;
//     v11 =  v7 + ONE;
//     for (int i = CHACHA_RNDS/2; i; i--) {
//       DQROUND_VECTORS(v0,v1,v2,v3)
//       DQROUND_VECTORS(v4,v5,v6,v7)
//       DQROUND_VECTORS(v8,v9,v10,v11)
//     }
//     WRITE_XOR(ip, op, 0, v0+s0, v1+s1, v2+s2, v3+s3)
//     s3 += ONE;
//     WRITE_XOR(ip, op, 16, v4+s0, v5+s1, v6+s2, v7+s3)
//     s3 += ONE;
//     WRITE_XOR(ip, op, 32, v8+s0, v9+s1, v10+s2, v11+s3)
//     s3 += ONE;
//     ip += VBPI*16;
//     op += VBPI*16;
//   }
//   for (size_t iters = 0; iters < nr_ser; iters++) {
//     vec v0 = s0, v1 = s1, v2 = s2, v3 = s3;
//     for (int i = CHACHA_RNDS/2; i; i--) {
//       DQROUND_VECTORS(v0,v1,v2,v3)
//     }
//     WRITE_XOR(ip, op, 0, v0+s0, v1+s1, v2+s2, v3+s3)
//     s3 += ONE;
//     ip += 16;
//     op += 16;
//   }
//   /* Upstream has code for dealing with non-block multiple lengths, but
//    * the caller handles that for us.  Likewise the caller handles updating
//    * the counter.
//    */
// }
//
import "C"
import "unsafe"

func blocksAmd64(x *[stateSize]uint32, in []byte, out []byte, nrBlocks int) {
	// XXX: This probably needs to be higher, since cgo has a silly amount of
	// overhead.  Oh well.
	if nrBlocks < 3 {
		blocksRef(x, in, out, nrBlocks)
		return
	}

	if in == nil {
		for i := range out {
			out[i] = 0
		}
		in = out
	}

	C.chacha_blocksAmd64((*C.uint32_t)(unsafe.Pointer(&x[0])),
		(*C.uint8_t)(unsafe.Pointer(&in[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		(C.size_t)(nrBlocks))

	// Stoping at 2^70 bytes per nonce is the user's responsibility.
	ctr := uint64(x[9])<<32 | uint64(x[8])
	ctr += uint64(nrBlocks)
	x[8] = uint32(ctr)
	x[9] = uint32(ctr >> 32)
}

func init() {
	// Only use the vectorized implementation when we are calculating at least
	// one block, since there's no speedup to be had without parallelization.
	blocksFn = blocksAmd64
	usingVectors = true
}
