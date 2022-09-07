#include "hash.h"
#include "_util.h"

#include <byteswap.h>
#include <stdint.h>
#include <stdlib.h>

// initial values
const uint32_t _RIPEMD128_INIT[4] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
const uint32_t _RIPEMD160_INIT[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
// round functions
#define _F1(x,y,z) (x ^ y ^ z)
#define _F2(x,y,z) ((x & y) | ((~x) & z))
#define _F3(x,y,z) ((x | (~y)) ^ z)
#define _F4(x,y,z) ((x & z) | (y & (~z)))
#define _F5(x,y,z) (x ^ (y | (~z)))
#define _ROTL(n,bits) ((n << bits) | (n >> (32 - bits)))
// perform round (128 bit)
#define _ROUND_L1_128(A,B,C,D,s,X) (A = _ROTL((A + _F1(B,C,D) + X + 0x00000000),s))
#define _ROUND_L2_128(A,B,C,D,s,X) (A = _ROTL((A + _F2(B,C,D) + X + 0x5A827999),s))
#define _ROUND_L3_128(A,B,C,D,s,X) (A = _ROTL((A + _F3(B,C,D) + X + 0x6ED9EBA1),s))
#define _ROUND_L4_128(A,B,C,D,s,X) (A = _ROTL((A + _F4(B,C,D) + X + 0x8F1BBCDC),s))
#define _ROUND_R1_128(A,B,C,D,s,X) (A = _ROTL((A + _F4(B,C,D) + X + 0x50A28BE6),s))
#define _ROUND_R2_128(A,B,C,D,s,X) (A = _ROTL((A + _F3(B,C,D) + X + 0x5C4DD124),s))
#define _ROUND_R3_128(A,B,C,D,s,X) (A = _ROTL((A + _F2(B,C,D) + X + 0x6D703EF3),s))
#define _ROUND_R4_128(A,B,C,D,s,X) (A = _ROTL((A + _F1(B,C,D) + X + 0x00000000),s))
// perform round (160 bit)
#define _ROUND_L1_160(A,B,C,D,E,s,X) (A = _ROTL((A + _F1(B,C,D) + X + 0x00000000),s) + E, C = _ROTL(C,10))
#define _ROUND_L2_160(A,B,C,D,E,s,X) (A = _ROTL((A + _F2(B,C,D) + X + 0x5A827999),s) + E, C = _ROTL(C,10))
#define _ROUND_L3_160(A,B,C,D,E,s,X) (A = _ROTL((A + _F3(B,C,D) + X + 0x6ED9EBA1),s) + E, C = _ROTL(C,10))
#define _ROUND_L4_160(A,B,C,D,E,s,X) (A = _ROTL((A + _F4(B,C,D) + X + 0X8F1BBCDC),s) + E, C = _ROTL(C,10))
#define _ROUND_L5_160(A,B,C,D,E,s,X) (A = _ROTL((A + _F5(B,C,D) + X + 0XA953FD4E),s) + E, C = _ROTL(C,10))
#define _ROUND_R1_160(A,B,C,D,E,s,X) (A = _ROTL((A + _F5(B,C,D) + X + 0x50A28BE6),s) + E, C = _ROTL(C,10))
#define _ROUND_R2_160(A,B,C,D,E,s,X) (A = _ROTL((A + _F4(B,C,D) + X + 0x5C4DD124),s) + E, C = _ROTL(C,10))
#define _ROUND_R3_160(A,B,C,D,E,s,X) (A = _ROTL((A + _F3(B,C,D) + X + 0x6D703EF3),s) + E, C = _ROTL(C,10))
#define _ROUND_R4_160(A,B,C,D,E,s,X) (A = _ROTL((A + _F2(B,C,D) + X + 0x7A6D76E9),s) + E, C = _ROTL(C,10))
#define _ROUND_R5_160(A,B,C,D,E,s,X) (A = _ROTL((A + _F1(B,C,D) + X + 0x00000000),s) + E, C = _ROTL(C,10))

void hash_ripemd128_block(uint32_t * restrict hash, const uint32_t * restrict M)
{
    uint32_t Al = hash[0], Bl = hash[1], Cl = hash[2], Dl = hash[3]; // left
    uint32_t Ar = hash[0], Br = hash[1], Cr = hash[2], Dr = hash[3]; // right
    uint32_t t;
    // round 1
    _ROUND_L1_128(Al,Bl,Cl,Dl,11,M[ 0]);
    _ROUND_R1_128(Ar,Br,Cr,Dr, 8,M[ 5]);
    _ROUND_L1_128(Dl,Al,Bl,Cl,14,M[ 1]);
    _ROUND_R1_128(Dr,Ar,Br,Cr, 9,M[14]);
    _ROUND_L1_128(Cl,Dl,Al,Bl,15,M[ 2]);
    _ROUND_R1_128(Cr,Dr,Ar,Br, 9,M[ 7]);
    _ROUND_L1_128(Bl,Cl,Dl,Al,12,M[ 3]);
    _ROUND_R1_128(Br,Cr,Dr,Ar,11,M[ 0]);
    _ROUND_L1_128(Al,Bl,Cl,Dl, 5,M[ 4]);
    _ROUND_R1_128(Ar,Br,Cr,Dr,13,M[ 9]);
    _ROUND_L1_128(Dl,Al,Bl,Cl, 8,M[ 5]);
    _ROUND_R1_128(Dr,Ar,Br,Cr,15,M[ 2]);
    _ROUND_L1_128(Cl,Dl,Al,Bl, 7,M[ 6]);
    _ROUND_R1_128(Cr,Dr,Ar,Br,15,M[11]);
    _ROUND_L1_128(Bl,Cl,Dl,Al, 9,M[ 7]);
    _ROUND_R1_128(Br,Cr,Dr,Ar, 5,M[ 4]);
    _ROUND_L1_128(Al,Bl,Cl,Dl,11,M[ 8]);
    _ROUND_R1_128(Ar,Br,Cr,Dr, 7,M[13]);
    _ROUND_L1_128(Dl,Al,Bl,Cl,13,M[ 9]);
    _ROUND_R1_128(Dr,Ar,Br,Cr, 7,M[ 6]);
    _ROUND_L1_128(Cl,Dl,Al,Bl,14,M[10]);
    _ROUND_R1_128(Cr,Dr,Ar,Br, 8,M[15]);
    _ROUND_L1_128(Bl,Cl,Dl,Al,15,M[11]);
    _ROUND_R1_128(Br,Cr,Dr,Ar,11,M[ 8]);
    _ROUND_L1_128(Al,Bl,Cl,Dl, 6,M[12]);
    _ROUND_R1_128(Ar,Br,Cr,Dr,14,M[ 1]);
    _ROUND_L1_128(Dl,Al,Bl,Cl, 7,M[13]);
    _ROUND_R1_128(Dr,Ar,Br,Cr,14,M[10]);
    _ROUND_L1_128(Cl,Dl,Al,Bl, 9,M[14]);
    _ROUND_R1_128(Cr,Dr,Ar,Br,12,M[ 3]);
    _ROUND_L1_128(Bl,Cl,Dl,Al, 8,M[15]);
    _ROUND_R1_128(Br,Cr,Dr,Ar, 6,M[12]);
    // round 2
    _ROUND_L2_128(Al,Bl,Cl,Dl, 7,M[ 7]);
    _ROUND_R2_128(Ar,Br,Cr,Dr, 9,M[ 6]);
    _ROUND_L2_128(Dl,Al,Bl,Cl, 6,M[ 4]);
    _ROUND_R2_128(Dr,Ar,Br,Cr,13,M[11]);
    _ROUND_L2_128(Cl,Dl,Al,Bl, 8,M[13]);
    _ROUND_R2_128(Cr,Dr,Ar,Br,15,M[ 3]);
    _ROUND_L2_128(Bl,Cl,Dl,Al,13,M[ 1]);
    _ROUND_R2_128(Br,Cr,Dr,Ar, 7,M[ 7]);
    _ROUND_L2_128(Al,Bl,Cl,Dl,11,M[10]);
    _ROUND_R2_128(Ar,Br,Cr,Dr,12,M[ 0]);
    _ROUND_L2_128(Dl,Al,Bl,Cl, 9,M[ 6]);
    _ROUND_R2_128(Dr,Ar,Br,Cr, 8,M[13]);
    _ROUND_L2_128(Cl,Dl,Al,Bl, 7,M[15]);
    _ROUND_R2_128(Cr,Dr,Ar,Br, 9,M[ 5]);
    _ROUND_L2_128(Bl,Cl,Dl,Al,15,M[ 3]);
    _ROUND_R2_128(Br,Cr,Dr,Ar,11,M[10]);
    _ROUND_L2_128(Al,Bl,Cl,Dl, 7,M[12]);
    _ROUND_R2_128(Ar,Br,Cr,Dr, 7,M[14]);
    _ROUND_L2_128(Dl,Al,Bl,Cl,12,M[ 0]);
    _ROUND_R2_128(Dr,Ar,Br,Cr, 7,M[15]);
    _ROUND_L2_128(Cl,Dl,Al,Bl,15,M[ 9]);
    _ROUND_R2_128(Cr,Dr,Ar,Br,12,M[ 8]);
    _ROUND_L2_128(Bl,Cl,Dl,Al, 9,M[ 5]);
    _ROUND_R2_128(Br,Cr,Dr,Ar, 7,M[12]);
    _ROUND_L2_128(Al,Bl,Cl,Dl,11,M[ 2]);
    _ROUND_R2_128(Ar,Br,Cr,Dr, 6,M[ 4]);
    _ROUND_L2_128(Dl,Al,Bl,Cl, 7,M[14]);
    _ROUND_R2_128(Dr,Ar,Br,Cr,15,M[ 9]);
    _ROUND_L2_128(Cl,Dl,Al,Bl,13,M[11]);
    _ROUND_R2_128(Cr,Dr,Ar,Br,13,M[ 1]);
    _ROUND_L2_128(Bl,Cl,Dl,Al,12,M[ 8]);
    _ROUND_R2_128(Br,Cr,Dr,Ar,11,M[ 2]);
    // round 3
    _ROUND_L3_128(Al,Bl,Cl,Dl,11,M[ 3]);
    _ROUND_R3_128(Ar,Br,Cr,Dr, 9,M[15]);
    _ROUND_L3_128(Dl,Al,Bl,Cl,13,M[10]);
    _ROUND_R3_128(Dr,Ar,Br,Cr, 7,M[ 5]);
    _ROUND_L3_128(Cl,Dl,Al,Bl, 6,M[14]);
    _ROUND_R3_128(Cr,Dr,Ar,Br,15,M[ 1]);
    _ROUND_L3_128(Bl,Cl,Dl,Al, 7,M[ 4]);
    _ROUND_R3_128(Br,Cr,Dr,Ar,11,M[ 3]);
    _ROUND_L3_128(Al,Bl,Cl,Dl,14,M[ 9]);
    _ROUND_R3_128(Ar,Br,Cr,Dr, 8,M[ 7]);
    _ROUND_L3_128(Dl,Al,Bl,Cl, 9,M[15]);
    _ROUND_R3_128(Dr,Ar,Br,Cr, 6,M[14]);
    _ROUND_L3_128(Cl,Dl,Al,Bl,13,M[ 8]);
    _ROUND_R3_128(Cr,Dr,Ar,Br, 6,M[ 6]);
    _ROUND_L3_128(Bl,Cl,Dl,Al,15,M[ 1]);
    _ROUND_R3_128(Br,Cr,Dr,Ar,14,M[ 9]);
    _ROUND_L3_128(Al,Bl,Cl,Dl,14,M[ 2]);
    _ROUND_R3_128(Ar,Br,Cr,Dr,12,M[11]);
    _ROUND_L3_128(Dl,Al,Bl,Cl, 8,M[ 7]);
    _ROUND_R3_128(Dr,Ar,Br,Cr,13,M[ 8]);
    _ROUND_L3_128(Cl,Dl,Al,Bl,13,M[ 0]);
    _ROUND_R3_128(Cr,Dr,Ar,Br, 5,M[12]);
    _ROUND_L3_128(Bl,Cl,Dl,Al, 6,M[ 6]);
    _ROUND_R3_128(Br,Cr,Dr,Ar,14,M[ 2]);
    _ROUND_L3_128(Al,Bl,Cl,Dl, 5,M[13]);
    _ROUND_R3_128(Ar,Br,Cr,Dr,13,M[10]);
    _ROUND_L3_128(Dl,Al,Bl,Cl,12,M[11]);
    _ROUND_R3_128(Dr,Ar,Br,Cr,13,M[ 0]);
    _ROUND_L3_128(Cl,Dl,Al,Bl, 7,M[ 5]);
    _ROUND_R3_128(Cr,Dr,Ar,Br, 7,M[ 4]);
    _ROUND_L3_128(Bl,Cl,Dl,Al, 5,M[12]);
    _ROUND_R3_128(Br,Cr,Dr,Ar, 5,M[13]);
    // round 4
    _ROUND_L4_128(Al,Bl,Cl,Dl,11,M[ 1]);
    _ROUND_R4_128(Ar,Br,Cr,Dr,15,M[ 8]);
    _ROUND_L4_128(Dl,Al,Bl,Cl,12,M[ 9]);
    _ROUND_R4_128(Dr,Ar,Br,Cr, 5,M[ 6]);
    _ROUND_L4_128(Cl,Dl,Al,Bl,14,M[11]);
    _ROUND_R4_128(Cr,Dr,Ar,Br, 8,M[ 4]);
    _ROUND_L4_128(Bl,Cl,Dl,Al,15,M[10]);
    _ROUND_R4_128(Br,Cr,Dr,Ar,11,M[ 1]);
    _ROUND_L4_128(Al,Bl,Cl,Dl,14,M[ 0]);
    _ROUND_R4_128(Ar,Br,Cr,Dr,14,M[ 3]);
    _ROUND_L4_128(Dl,Al,Bl,Cl,15,M[ 8]);
    _ROUND_R4_128(Dr,Ar,Br,Cr,14,M[11]);
    _ROUND_L4_128(Cl,Dl,Al,Bl, 9,M[12]);
    _ROUND_R4_128(Cr,Dr,Ar,Br, 6,M[15]);
    _ROUND_L4_128(Bl,Cl,Dl,Al, 8,M[ 4]);
    _ROUND_R4_128(Br,Cr,Dr,Ar,14,M[ 0]);
    _ROUND_L4_128(Al,Bl,Cl,Dl, 9,M[13]);
    _ROUND_R4_128(Ar,Br,Cr,Dr, 6,M[ 5]);
    _ROUND_L4_128(Dl,Al,Bl,Cl,14,M[ 3]);
    _ROUND_R4_128(Dr,Ar,Br,Cr, 9,M[12]);
    _ROUND_L4_128(Cl,Dl,Al,Bl, 5,M[ 7]);
    _ROUND_R4_128(Cr,Dr,Ar,Br,12,M[ 2]);
    _ROUND_L4_128(Bl,Cl,Dl,Al, 6,M[15]);
    _ROUND_R4_128(Br,Cr,Dr,Ar, 9,M[13]);
    _ROUND_L4_128(Al,Bl,Cl,Dl, 8,M[14]);
    _ROUND_R4_128(Ar,Br,Cr,Dr,12,M[ 9]);
    _ROUND_L4_128(Dl,Al,Bl,Cl, 6,M[ 5]);
    _ROUND_R4_128(Dr,Ar,Br,Cr, 5,M[ 7]);
    _ROUND_L4_128(Cl,Dl,Al,Bl, 5,M[ 6]);
    _ROUND_R4_128(Cr,Dr,Ar,Br,15,M[10]);
    _ROUND_L4_128(Bl,Cl,Dl,Al,12,M[ 2]);
    _ROUND_R4_128(Br,Cr,Dr,Ar, 8,M[14]);
    // update cumulative hash
    t = hash[1] + Cl + Dr;
    hash[1] = hash[2] + Dl + Ar;
    hash[2] = hash[3] + Al + Br;
    hash[3] = hash[0] + Bl + Cr;
    hash[0] = t;
}

void hash_ripemd160_block(uint32_t * restrict hash, const uint32_t * restrict M)
{
    uint32_t Al = hash[0], Bl = hash[1], Cl = hash[2], Dl = hash[3], El = hash[4]; // left
    uint32_t Ar = hash[0], Br = hash[1], Cr = hash[2], Dr = hash[3], Er = hash[4]; // right
    uint32_t t;
    // round 1
    _ROUND_L1_160(Al,Bl,Cl,Dl,El,11,M[ 0]);
    _ROUND_R1_160(Ar,Br,Cr,Dr,Er, 8,M[ 5]);
    _ROUND_L1_160(El,Al,Bl,Cl,Dl,14,M[ 1]);
    _ROUND_R1_160(Er,Ar,Br,Cr,Dr, 9,M[14]);
    _ROUND_L1_160(Dl,El,Al,Bl,Cl,15,M[ 2]);
    _ROUND_R1_160(Dr,Er,Ar,Br,Cr, 9,M[ 7]);
    _ROUND_L1_160(Cl,Dl,El,Al,Bl,12,M[ 3]);
    _ROUND_R1_160(Cr,Dr,Er,Ar,Br,11,M[ 0]);
    _ROUND_L1_160(Bl,Cl,Dl,El,Al, 5,M[ 4]);
    _ROUND_R1_160(Br,Cr,Dr,Er,Ar,13,M[ 9]);
    _ROUND_L1_160(Al,Bl,Cl,Dl,El, 8,M[ 5]);
    _ROUND_R1_160(Ar,Br,Cr,Dr,Er,15,M[ 2]);
    _ROUND_L1_160(El,Al,Bl,Cl,Dl, 7,M[ 6]);
    _ROUND_R1_160(Er,Ar,Br,Cr,Dr,15,M[11]);
    _ROUND_L1_160(Dl,El,Al,Bl,Cl, 9,M[ 7]);
    _ROUND_R1_160(Dr,Er,Ar,Br,Cr, 5,M[ 4]);
    _ROUND_L1_160(Cl,Dl,El,Al,Bl,11,M[ 8]);
    _ROUND_R1_160(Cr,Dr,Er,Ar,Br, 7,M[13]);
    _ROUND_L1_160(Bl,Cl,Dl,El,Al,13,M[ 9]);
    _ROUND_R1_160(Br,Cr,Dr,Er,Ar, 7,M[ 6]);
    _ROUND_L1_160(Al,Bl,Cl,Dl,El,14,M[10]);
    _ROUND_R1_160(Ar,Br,Cr,Dr,Er, 8,M[15]);
    _ROUND_L1_160(El,Al,Bl,Cl,Dl,15,M[11]);
    _ROUND_R1_160(Er,Ar,Br,Cr,Dr,11,M[ 8]);
    _ROUND_L1_160(Dl,El,Al,Bl,Cl, 6,M[12]);
    _ROUND_R1_160(Dr,Er,Ar,Br,Cr,14,M[ 1]);
    _ROUND_L1_160(Cl,Dl,El,Al,Bl, 7,M[13]);
    _ROUND_R1_160(Cr,Dr,Er,Ar,Br,14,M[10]);
    _ROUND_L1_160(Bl,Cl,Dl,El,Al, 9,M[14]);
    _ROUND_R1_160(Br,Cr,Dr,Er,Ar,12,M[ 3]);
    _ROUND_L1_160(Al,Bl,Cl,Dl,El, 8,M[15]);
    _ROUND_R1_160(Ar,Br,Cr,Dr,Er, 6,M[12]);
    // round 2
    _ROUND_L2_160(El,Al,Bl,Cl,Dl, 7,M[ 7]);
    _ROUND_R2_160(Er,Ar,Br,Cr,Dr, 9,M[ 6]);
    _ROUND_L2_160(Dl,El,Al,Bl,Cl, 6,M[ 4]);
    _ROUND_R2_160(Dr,Er,Ar,Br,Cr,13,M[11]);
    _ROUND_L2_160(Cl,Dl,El,Al,Bl, 8,M[13]);
    _ROUND_R2_160(Cr,Dr,Er,Ar,Br,15,M[ 3]);
    _ROUND_L2_160(Bl,Cl,Dl,El,Al,13,M[ 1]);
    _ROUND_R2_160(Br,Cr,Dr,Er,Ar, 7,M[ 7]);
    _ROUND_L2_160(Al,Bl,Cl,Dl,El,11,M[10]);
    _ROUND_R2_160(Ar,Br,Cr,Dr,Er,12,M[ 0]);
    _ROUND_L2_160(El,Al,Bl,Cl,Dl, 9,M[ 6]);
    _ROUND_R2_160(Er,Ar,Br,Cr,Dr, 8,M[13]);
    _ROUND_L2_160(Dl,El,Al,Bl,Cl, 7,M[15]);
    _ROUND_R2_160(Dr,Er,Ar,Br,Cr, 9,M[ 5]);
    _ROUND_L2_160(Cl,Dl,El,Al,Bl,15,M[ 3]);
    _ROUND_R2_160(Cr,Dr,Er,Ar,Br,11,M[10]);
    _ROUND_L2_160(Bl,Cl,Dl,El,Al, 7,M[12]);
    _ROUND_R2_160(Br,Cr,Dr,Er,Ar, 7,M[14]);
    _ROUND_L2_160(Al,Bl,Cl,Dl,El,12,M[ 0]);
    _ROUND_R2_160(Ar,Br,Cr,Dr,Er, 7,M[15]);
    _ROUND_L2_160(El,Al,Bl,Cl,Dl,15,M[ 9]);
    _ROUND_R2_160(Er,Ar,Br,Cr,Dr,12,M[ 8]);
    _ROUND_L2_160(Dl,El,Al,Bl,Cl, 9,M[ 5]);
    _ROUND_R2_160(Dr,Er,Ar,Br,Cr, 7,M[12]);
    _ROUND_L2_160(Cl,Dl,El,Al,Bl,11,M[ 2]);
    _ROUND_R2_160(Cr,Dr,Er,Ar,Br, 6,M[ 4]);
    _ROUND_L2_160(Bl,Cl,Dl,El,Al, 7,M[14]);
    _ROUND_R2_160(Br,Cr,Dr,Er,Ar,15,M[ 9]);
    _ROUND_L2_160(Al,Bl,Cl,Dl,El,13,M[11]);
    _ROUND_R2_160(Ar,Br,Cr,Dr,Er,13,M[ 1]);
    _ROUND_L2_160(El,Al,Bl,Cl,Dl,12,M[ 8]);
    _ROUND_R2_160(Er,Ar,Br,Cr,Dr,11,M[ 2]);
    // round 3
    _ROUND_L3_160(Dl,El,Al,Bl,Cl,11,M[ 3]);
    _ROUND_R3_160(Dr,Er,Ar,Br,Cr, 9,M[15]);
    _ROUND_L3_160(Cl,Dl,El,Al,Bl,13,M[10]);
    _ROUND_R3_160(Cr,Dr,Er,Ar,Br, 7,M[ 5]);
    _ROUND_L3_160(Bl,Cl,Dl,El,Al, 6,M[14]);
    _ROUND_R3_160(Br,Cr,Dr,Er,Ar,15,M[ 1]);
    _ROUND_L3_160(Al,Bl,Cl,Dl,El, 7,M[ 4]);
    _ROUND_R3_160(Ar,Br,Cr,Dr,Er,11,M[ 3]);
    _ROUND_L3_160(El,Al,Bl,Cl,Dl,14,M[ 9]);
    _ROUND_R3_160(Er,Ar,Br,Cr,Dr, 8,M[ 7]);
    _ROUND_L3_160(Dl,El,Al,Bl,Cl, 9,M[15]);
    _ROUND_R3_160(Dr,Er,Ar,Br,Cr, 6,M[14]);
    _ROUND_L3_160(Cl,Dl,El,Al,Bl,13,M[ 8]);
    _ROUND_R3_160(Cr,Dr,Er,Ar,Br, 6,M[ 6]);
    _ROUND_L3_160(Bl,Cl,Dl,El,Al,15,M[ 1]);
    _ROUND_R3_160(Br,Cr,Dr,Er,Ar,14,M[ 9]);
    _ROUND_L3_160(Al,Bl,Cl,Dl,El,14,M[ 2]);
    _ROUND_R3_160(Ar,Br,Cr,Dr,Er,12,M[11]);
    _ROUND_L3_160(El,Al,Bl,Cl,Dl, 8,M[ 7]);
    _ROUND_R3_160(Er,Ar,Br,Cr,Dr,13,M[ 8]);
    _ROUND_L3_160(Dl,El,Al,Bl,Cl,13,M[ 0]);
    _ROUND_R3_160(Dr,Er,Ar,Br,Cr, 5,M[12]);
    _ROUND_L3_160(Cl,Dl,El,Al,Bl, 6,M[ 6]);
    _ROUND_R3_160(Cr,Dr,Er,Ar,Br,14,M[ 2]);
    _ROUND_L3_160(Bl,Cl,Dl,El,Al, 5,M[13]);
    _ROUND_R3_160(Br,Cr,Dr,Er,Ar,13,M[10]);
    _ROUND_L3_160(Al,Bl,Cl,Dl,El,12,M[11]);
    _ROUND_R3_160(Ar,Br,Cr,Dr,Er,13,M[ 0]);
    _ROUND_L3_160(El,Al,Bl,Cl,Dl, 7,M[ 5]);
    _ROUND_R3_160(Er,Ar,Br,Cr,Dr, 7,M[ 4]);
    _ROUND_L3_160(Dl,El,Al,Bl,Cl, 5,M[12]);
    _ROUND_R3_160(Dr,Er,Ar,Br,Cr, 5,M[13]);
    // round 4
    _ROUND_L4_160(Cl,Dl,El,Al,Bl,11,M[ 1]);
    _ROUND_R4_160(Cr,Dr,Er,Ar,Br,15,M[ 8]);
    _ROUND_L4_160(Bl,Cl,Dl,El,Al,12,M[ 9]);
    _ROUND_R4_160(Br,Cr,Dr,Er,Ar, 5,M[ 6]);
    _ROUND_L4_160(Al,Bl,Cl,Dl,El,14,M[11]);
    _ROUND_R4_160(Ar,Br,Cr,Dr,Er, 8,M[ 4]);
    _ROUND_L4_160(El,Al,Bl,Cl,Dl,15,M[10]);
    _ROUND_R4_160(Er,Ar,Br,Cr,Dr,11,M[ 1]);
    _ROUND_L4_160(Dl,El,Al,Bl,Cl,14,M[ 0]);
    _ROUND_R4_160(Dr,Er,Ar,Br,Cr,14,M[ 3]);
    _ROUND_L4_160(Cl,Dl,El,Al,Bl,15,M[ 8]);
    _ROUND_R4_160(Cr,Dr,Er,Ar,Br,14,M[11]);
    _ROUND_L4_160(Bl,Cl,Dl,El,Al, 9,M[12]);
    _ROUND_R4_160(Br,Cr,Dr,Er,Ar, 6,M[15]);
    _ROUND_L4_160(Al,Bl,Cl,Dl,El, 8,M[ 4]);
    _ROUND_R4_160(Ar,Br,Cr,Dr,Er,14,M[ 0]);
    _ROUND_L4_160(El,Al,Bl,Cl,Dl, 9,M[13]);
    _ROUND_R4_160(Er,Ar,Br,Cr,Dr, 6,M[ 5]);
    _ROUND_L4_160(Dl,El,Al,Bl,Cl,14,M[ 3]);
    _ROUND_R4_160(Dr,Er,Ar,Br,Cr, 9,M[12]);
    _ROUND_L4_160(Cl,Dl,El,Al,Bl, 5,M[ 7]);
    _ROUND_R4_160(Cr,Dr,Er,Ar,Br,12,M[ 2]);
    _ROUND_L4_160(Bl,Cl,Dl,El,Al, 6,M[15]);
    _ROUND_R4_160(Br,Cr,Dr,Er,Ar, 9,M[13]);
    _ROUND_L4_160(Al,Bl,Cl,Dl,El, 8,M[14]);
    _ROUND_R4_160(Ar,Br,Cr,Dr,Er,12,M[ 9]);
    _ROUND_L4_160(El,Al,Bl,Cl,Dl, 6,M[ 5]);
    _ROUND_R4_160(Er,Ar,Br,Cr,Dr, 5,M[ 7]);
    _ROUND_L4_160(Dl,El,Al,Bl,Cl, 5,M[ 6]);
    _ROUND_R4_160(Dr,Er,Ar,Br,Cr,15,M[10]);
    _ROUND_L4_160(Cl,Dl,El,Al,Bl,12,M[ 2]);
    _ROUND_R4_160(Cr,Dr,Er,Ar,Br, 8,M[14]);
    // round 5
    _ROUND_L5_160(Bl,Cl,Dl,El,Al, 9,M[ 4]);
    _ROUND_R5_160(Br,Cr,Dr,Er,Ar, 8,M[12]);
    _ROUND_L5_160(Al,Bl,Cl,Dl,El,15,M[ 0]);
    _ROUND_R5_160(Ar,Br,Cr,Dr,Er, 5,M[15]);
    _ROUND_L5_160(El,Al,Bl,Cl,Dl, 5,M[ 5]);
    _ROUND_R5_160(Er,Ar,Br,Cr,Dr,12,M[10]);
    _ROUND_L5_160(Dl,El,Al,Bl,Cl,11,M[ 9]);
    _ROUND_R5_160(Dr,Er,Ar,Br,Cr, 9,M[ 4]);
    _ROUND_L5_160(Cl,Dl,El,Al,Bl, 6,M[ 7]);
    _ROUND_R5_160(Cr,Dr,Er,Ar,Br,12,M[ 1]);
    _ROUND_L5_160(Bl,Cl,Dl,El,Al, 8,M[12]);
    _ROUND_R5_160(Br,Cr,Dr,Er,Ar, 5,M[ 5]);
    _ROUND_L5_160(Al,Bl,Cl,Dl,El,13,M[ 2]);
    _ROUND_R5_160(Ar,Br,Cr,Dr,Er,14,M[ 8]);
    _ROUND_L5_160(El,Al,Bl,Cl,Dl,12,M[10]);
    _ROUND_R5_160(Er,Ar,Br,Cr,Dr, 6,M[ 7]);
    _ROUND_L5_160(Dl,El,Al,Bl,Cl, 5,M[14]);
    _ROUND_R5_160(Dr,Er,Ar,Br,Cr, 8,M[ 6]);
    _ROUND_L5_160(Cl,Dl,El,Al,Bl,12,M[ 1]);
    _ROUND_R5_160(Cr,Dr,Er,Ar,Br,13,M[ 2]);
    _ROUND_L5_160(Bl,Cl,Dl,El,Al,13,M[ 3]);
    _ROUND_R5_160(Br,Cr,Dr,Er,Ar, 6,M[13]);
    _ROUND_L5_160(Al,Bl,Cl,Dl,El,14,M[ 8]);
    _ROUND_R5_160(Ar,Br,Cr,Dr,Er, 5,M[14]);
    _ROUND_L5_160(El,Al,Bl,Cl,Dl,11,M[11]);
    _ROUND_R5_160(Er,Ar,Br,Cr,Dr,15,M[ 0]);
    _ROUND_L5_160(Dl,El,Al,Bl,Cl, 8,M[ 6]);
    _ROUND_R5_160(Dr,Er,Ar,Br,Cr,13,M[ 3]);
    _ROUND_L5_160(Cl,Dl,El,Al,Bl, 5,M[15]);
    _ROUND_R5_160(Cr,Dr,Er,Ar,Br,11,M[ 9]);
    _ROUND_L5_160(Bl,Cl,Dl,El,Al, 6,M[13]);
    _ROUND_R5_160(Br,Cr,Dr,Er,Ar,11,M[11]);
    // update cumulative hash
    t = hash[1] + Cl + Dr;
    hash[1] = hash[2] + Dl + Er;
    hash[2] = hash[3] + El + Ar;
    hash[3] = hash[4] + Al + Br;
    hash[4] = hash[0] + Bl + Cr;
    hash[0] = t;
}

// hash must be a 16 byte array
void hash_ripemd128_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash)
{
    const uint8_t *end = array + len;
    const uint8_t *block = array;
    uint32_t h[4];
    memcpy(h,_RIPEMD128_INIT,16);
    while (block + 64 <= end)
    {
        hash_ripemd128_block(h,(uint32_t*)block);
        block += 64;
    }
    // padding
    uint8_t buf[128];
    size_t buf_len = 0;
    size_t block_len = end - block;
    _pad1(buf,&buf_len,block,block_len,len<<3);
    hash_ripemd128_block(h,(uint32_t*)buf);
    if (buf_len == 128)
        hash_ripemd128_block(h,(uint32_t*)buf+16);
    memcpy(hash,h,16);
}

// hash must be a 20 byte array
void hash_ripemd160_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash)
{
    const uint8_t *end = array + len;
    const uint8_t *block = array;
    uint32_t h[5];
    memcpy(h,_RIPEMD160_INIT,20);
    while (block + 64 <= end)
    {
        hash_ripemd160_block(h,(uint32_t*)block);
        block += 64;
    }
    // padding
    uint8_t buf[128];
    size_t buf_len = 0;
    size_t block_len = end - block;
    _pad1(buf,&buf_len,block,block_len,len<<3);
    hash_ripemd160_block(h,(uint32_t*)buf);
    if (buf_len == 128)
        hash_ripemd160_block(h,(uint32_t*)buf+16);
    memcpy(hash,h,20);
}
