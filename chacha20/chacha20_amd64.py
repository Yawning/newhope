#!/usr/bin/env python3
#
# To the extent possible under law, Yawning Angel has waived all copyright
# and related or neighboring rights to chacha20, using the Creative
# Commons "CC0" public domain dedication. See LICENSE or
# <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

#
# Ok.  The first revision of this code started off as a cgo version of Ted
# Krovetz's vec128 ChaCha20 implementation, but cgo sucks because it carves
# off a separate stack (needed, but expensive), and worse, can allocate an OS
# thread because it treats all cgo invocations as system calls.
#
# For something like a low level cryptography routine, both of these behaviors
# are just unneccecary overhead, and the latter is totally fucking retarded.
#
# Since Golang doesn't have SIMD intrinsics, this means, that it's either
# "learn plan 9 assembly", or resort to more extreme measures like using a
# python code generator.  This obviously goes for the latter.
#
# Dependencies: https://github.com/Maratyszcza/PeachPy
#
# python3 -m peachpy.x86_64 -mabi=goasm -S -o chacha20_amd64.s chacha20_amd64.py
#

from peachpy import *
from peachpy.x86_64 import *

sigma = Argument(ptr(const_uint32_t))
one = Argument(ptr(const_uint32_t))
x = Argument(ptr(uint32_t))
inp = Argument(ptr(const_uint8_t))
outp = Argument(ptr(uint8_t))
nrBlocks = Argument(ptr(size_t))

def RotV1(x):
    PSHUFD(x, x, 0x39)

def RotV2(x):
    PSHUFD(x, x, 0x4e)

def RotV3(x):
    PSHUFD(x, x, 0x93)

def RotW7(tmp, x):
    MOVDQA(tmp, x)
    PSLLD(tmp, 7)
    PSRLD(x, 25)
    PXOR(x, tmp)

def RotW8(tmp, x):
    MOVDQA(tmp, x)
    PSLLD(tmp, 8)
    PSRLD(x, 24)
    PXOR(x, tmp)

def RotW12(tmp, x):
    MOVDQA(tmp, x)
    PSLLD(tmp, 12)
    PSRLD(x, 20)
    PXOR(x, tmp)

def RotW16(tmp, x):
    MOVDQA(tmp, x)
    PSLLD(tmp, 16)
    PSRLD(x, 16)
    PXOR(x, tmp)

def DQRoundVectors(tmp, a, b, c, d):
    # a += b; d ^= a; d = ROTW16(d);
    PADDD(a, b)
    PXOR(d, a)
    RotW16(tmp, d)

    # c += d; b ^= c; b = ROTW12(b);
    PADDD(c, d)
    PXOR(b, c)
    RotW12(tmp, b)

    # a += b; d ^= a; d = ROTW8(d);
    PADDD(a, b)
    PXOR(d, a)
    RotW8(tmp, d)

    # c += d; b ^= c; b = ROTW7(b)
    PADDD(c, d)
    PXOR(b, c)
    RotW7(tmp, b)

    # b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);
    RotV1(b)
    RotV2(c)
    RotV3(d)

    # a += b; d ^= a; d = ROTW16(d);
    PADDD(a, b)
    PXOR(d, a)
    RotW16(tmp, d)

    # c += d; b ^= c; b = ROTW12(b);
    PADDD(c, d)
    PXOR(b, c)
    RotW12(tmp, b)

    # a += b; d ^= a; d = ROTW8(d);
    PADDD(a, b)
    PXOR(d, a)
    RotW8(tmp, d)

    # c += d; b ^= c; b = ROTW7(b);
    PADDD(c, d)
    PXOR(b, c)
    RotW7(tmp, b)

    # b = ROTV3(b); c = ROTV2(c); d = ROTV1(d);
    RotV3(b)
    RotV2(c)
    RotV1(d)

def WriteXor(tmp, inp, outp, d, v0, v1, v2, v3):
    MOVDQU(tmp, [inp+d])
    PXOR(tmp, v0)
    MOVDQU([outp+d], tmp)
    MOVDQU(tmp, [inp+d+16])
    PXOR(tmp, v1)
    MOVDQU([outp+d+16], tmp)
    MOVDQU(tmp, [inp+d+32])
    PXOR(tmp, v2)
    MOVDQU([outp+d+32], tmp)
    MOVDQU(tmp, [inp+d+48])
    PXOR(tmp, v3)
    MOVDQU([outp+d+48], tmp)

with Function("blocksAmd64SSE2", (sigma, one, x, inp, outp, nrBlocks)):
    reg_sigma = GeneralPurposeRegister64()
    reg_one = GeneralPurposeRegister64()
    reg_x = GeneralPurposeRegister64()
    reg_inp = GeneralPurposeRegister64()
    reg_outp = GeneralPurposeRegister64()
    reg_blocks = GeneralPurposeRegister64()

    LOAD.ARGUMENT(reg_sigma, sigma)
    LOAD.ARGUMENT(reg_one, one)
    LOAD.ARGUMENT(reg_x, x)
    LOAD.ARGUMENT(reg_inp, inp)
    LOAD.ARGUMENT(reg_outp, outp)
    LOAD.ARGUMENT(reg_blocks, nrBlocks)

    xmm_tmp = XMMRegister()
    xmm_s1 = XMMRegister()
    MOVDQU(xmm_s1, [reg_x])
    xmm_s2 = XMMRegister()
    MOVDQU(xmm_s2, [reg_x+16])
    xmm_s3 = XMMRegister()
    MOVDQU(xmm_s3, [reg_x+32])

    vector_loop = Loop()
    serial_loop = Loop()

    xmm_v0 = XMMRegister()
    xmm_v1 = XMMRegister()
    xmm_v2 = XMMRegister()
    xmm_v3 = XMMRegister()

    SUB(reg_blocks, 3)
    JB(vector_loop.end)
    with vector_loop:
        MOVDQU(xmm_v0, [reg_sigma])
        MOVDQA(xmm_v1, xmm_s1)
        MOVDQA(xmm_v2, xmm_s2)
        MOVDQA(xmm_v3, xmm_s3)

        xmm_v4 = XMMRegister()
        MOVDQU(xmm_v4, [reg_sigma])
        xmm_v5 = XMMRegister()
        MOVDQA(xmm_v5, xmm_s1)
        xmm_v6 = XMMRegister()
        MOVDQA(xmm_v6, xmm_s2)
        xmm_v7 = XMMRegister()
        MOVDQA(xmm_v7, xmm_s3)
        PADDQ(xmm_v7, [reg_one])

        xmm_v8 = XMMRegister()
        MOVDQU(xmm_v8, [reg_sigma])
        xmm_v9 = XMMRegister()
        MOVDQA(xmm_v9, xmm_s1)
        xmm_v10 = XMMRegister()
        MOVDQA(xmm_v10, xmm_s2)
        xmm_v11 = XMMRegister()
        MOVDQA(xmm_v11, xmm_v7)
        PADDQ(xmm_v11, [reg_one])

        reg_rounds = GeneralPurposeRegister64()
        MOV(reg_rounds, 20)
        rounds_loop = Loop()
        with rounds_loop:
            DQRoundVectors(xmm_tmp, xmm_v0, xmm_v1, xmm_v2, xmm_v3)
            DQRoundVectors(xmm_tmp, xmm_v4, xmm_v5, xmm_v6, xmm_v7)
            DQRoundVectors(xmm_tmp, xmm_v8, xmm_v9, xmm_v10, xmm_v11)
            SUB(reg_rounds, 2)
            JNZ(rounds_loop.begin)

        PADDD(xmm_v0, [reg_sigma])
        PADDD(xmm_v1, xmm_s1)
        PADDD(xmm_v2, xmm_s2)
        PADDD(xmm_v3, xmm_s3)
        WriteXor(xmm_tmp, reg_inp, reg_outp, 0, xmm_v0, xmm_v1, xmm_v2, xmm_v3)
        PADDQ(xmm_s3, [reg_one])

        PADDD(xmm_v4, [reg_sigma])
        PADDD(xmm_v5, xmm_s1)
        PADDD(xmm_v6, xmm_s2)
        PADDD(xmm_v7, xmm_s3)
        WriteXor(xmm_tmp, reg_inp, reg_outp, 64, xmm_v4, xmm_v5, xmm_v6, xmm_v7)
        PADDQ(xmm_s3, [reg_one])

        PADDD(xmm_v8, [reg_sigma])
        PADDD(xmm_v9, xmm_s1)
        PADDD(xmm_v10, xmm_s2)
        PADDD(xmm_v11, xmm_s3)
        WriteXor(xmm_tmp, reg_inp, reg_outp, 128, xmm_v8, xmm_v9, xmm_v10, xmm_v11)
        PADDQ(xmm_s3, [reg_one])

        ADD(reg_inp, 192)
        ADD(reg_outp, 192)

        SUB(reg_blocks, 3)
        JAE(vector_loop.begin)

    ADD(reg_blocks, 3)
    JZ(serial_loop.end)

    with serial_loop:
        MOVDQU(xmm_v0, [reg_sigma])
        MOVDQA(xmm_v1, xmm_s1)
        MOVDQA(xmm_v2, xmm_s2)
        MOVDQA(xmm_v3, xmm_s3)

        reg_rounds = GeneralPurposeRegister64()
        MOV(reg_rounds, 20)
        rounds_loop = Loop()
        with rounds_loop:
            DQRoundVectors(xmm_tmp, xmm_v0, xmm_v1, xmm_v2, xmm_v3)
            SUB(reg_rounds, 2)
            JNZ(rounds_loop.begin)

        PADDD(xmm_v0, [reg_sigma])
        PADDD(xmm_v1, xmm_s1)
        PADDD(xmm_v2, xmm_s2)
        PADDD(xmm_v3, xmm_s3)
        WriteXor(xmm_tmp, reg_inp, reg_outp, 0, xmm_v0, xmm_v1, xmm_v2, xmm_v3)
        PADDQ(xmm_s3, [reg_one])

        ADD(reg_inp, 64)
        ADD(reg_outp, 64)

        SUB(reg_blocks, 1)
        JNZ(serial_loop.begin)

    # Write back the updated counter.  Stoping at 2^70 bytes is the user's
    # problem, not mine.
    MOVDQU([reg_x+32], xmm_s3)

    RETURN()
