#include "hash.h"
#include "_util.h"

#include <byteswap.h>
#include <stdint.h>
#include <stdlib.h>

// initial values
const uint32_t _RIPEMD160_INIT[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
// round functions
#define _F1(x,y,z) (x ^ y ^ z)
#define _F2(x,y,z) ((x & y) | ((~x) & z))
#define _F3(x,y,z) ((x | (~y)) ^ z)
#define _F4(x,y,z) ((x & z) | (y & (~z)))
#define _F5(x,y,z) (x ^ (y | (~z)))
#define _ROTL(n,bits) ((n << bits) | (n >> (32 - bits)))
// perform round
#define _ROUND_L1(A,B,C,D,E,s,X) (A = _ROTL((A + _F1(B,C,D) + X + 0x00000000),s) + E, C = _ROTL(C,10))
#define _ROUND_L2(A,B,C,D,E,s,X) (A = _ROTL((A + _F2(B,C,D) + X + 0x5A827999),s) + E, C = _ROTL(C,10))
#define _ROUND_L3(A,B,C,D,E,s,X) (A = _ROTL((A + _F3(B,C,D) + X + 0x6ED9EBA1),s) + E, C = _ROTL(C,10))
#define _ROUND_L4(A,B,C,D,E,s,X) (A = _ROTL((A + _F4(B,C,D) + X + 0X8F1BBCDC),s) + E, C = _ROTL(C,10))
#define _ROUND_L5(A,B,C,D,E,s,X) (A = _ROTL((A + _F5(B,C,D) + X + 0XA953FD4E),s) + E, C = _ROTL(C,10))
#define _ROUND_R1(A,B,C,D,E,s,X) (A = _ROTL((A + _F5(B,C,D) + X + 0x50A28BE6),s) + E, C = _ROTL(C,10))
#define _ROUND_R2(A,B,C,D,E,s,X) (A = _ROTL((A + _F4(B,C,D) + X + 0x5C4DD124),s) + E, C = _ROTL(C,10))
#define _ROUND_R3(A,B,C,D,E,s,X) (A = _ROTL((A + _F3(B,C,D) + X + 0x6D703EF3),s) + E, C = _ROTL(C,10))
#define _ROUND_R4(A,B,C,D,E,s,X) (A = _ROTL((A + _F2(B,C,D) + X + 0x7A6D76E9),s) + E, C = _ROTL(C,10))
#define _ROUND_R5(A,B,C,D,E,s,X) (A = _ROTL((A + _F1(B,C,D) + X + 0x00000000),s) + E, C = _ROTL(C,10))

void hash_ripemd160_block(uint32_t * restrict hash, const uint32_t * restrict M)
{
    uint32_t Al = hash[0], Bl = hash[1], Cl = hash[2], Dl = hash[3], El = hash[4]; // left
    uint32_t Ar = hash[0], Br = hash[1], Cr = hash[2], Dr = hash[3], Er = hash[4]; // right
    uint32_t t;
    // round 1
    _ROUND_L1(Al,Bl,Cl,Dl,El,11,M[ 0]);
    _ROUND_R1(Ar,Br,Cr,Dr,Er, 8,M[ 5]);
    _ROUND_L1(El,Al,Bl,Cl,Dl,14,M[ 1]);
    _ROUND_R1(Er,Ar,Br,Cr,Dr, 9,M[14]);
    _ROUND_L1(Dl,El,Al,Bl,Cl,15,M[ 2]);
    _ROUND_R1(Dr,Er,Ar,Br,Cr, 9,M[ 7]);
    _ROUND_L1(Cl,Dl,El,Al,Bl,12,M[ 3]);
    _ROUND_R1(Cr,Dr,Er,Ar,Br,11,M[ 0]);
    _ROUND_L1(Bl,Cl,Dl,El,Al, 5,M[ 4]);
    _ROUND_R1(Br,Cr,Dr,Er,Ar,13,M[ 9]);
    _ROUND_L1(Al,Bl,Cl,Dl,El, 8,M[ 5]);
    _ROUND_R1(Ar,Br,Cr,Dr,Er,15,M[ 2]);
    _ROUND_L1(El,Al,Bl,Cl,Dl, 7,M[ 6]);
    _ROUND_R1(Er,Ar,Br,Cr,Dr,15,M[11]);
    _ROUND_L1(Dl,El,Al,Bl,Cl, 9,M[ 7]);
    _ROUND_R1(Dr,Er,Ar,Br,Cr, 5,M[ 4]);
    _ROUND_L1(Cl,Dl,El,Al,Bl,11,M[ 8]);
    _ROUND_R1(Cr,Dr,Er,Ar,Br, 7,M[13]);
    _ROUND_L1(Bl,Cl,Dl,El,Al,13,M[ 9]);
    _ROUND_R1(Br,Cr,Dr,Er,Ar, 7,M[ 6]);
    _ROUND_L1(Al,Bl,Cl,Dl,El,14,M[10]);
    _ROUND_R1(Ar,Br,Cr,Dr,Er, 8,M[15]);
    _ROUND_L1(El,Al,Bl,Cl,Dl,15,M[11]);
    _ROUND_R1(Er,Ar,Br,Cr,Dr,11,M[ 8]);
    _ROUND_L1(Dl,El,Al,Bl,Cl, 6,M[12]);
    _ROUND_R1(Dr,Er,Ar,Br,Cr,14,M[ 1]);
    _ROUND_L1(Cl,Dl,El,Al,Bl, 7,M[13]);
    _ROUND_R1(Cr,Dr,Er,Ar,Br,14,M[10]);
    _ROUND_L1(Bl,Cl,Dl,El,Al, 9,M[14]);
    _ROUND_R1(Br,Cr,Dr,Er,Ar,12,M[ 3]);
    _ROUND_L1(Al,Bl,Cl,Dl,El, 8,M[15]);
    _ROUND_R1(Ar,Br,Cr,Dr,Er, 6,M[12]);
    // round 2
    _ROUND_L2(El,Al,Bl,Cl,Dl, 7,M[ 7]);
    _ROUND_R2(Er,Ar,Br,Cr,Dr, 9,M[ 6]);
    _ROUND_L2(Dl,El,Al,Bl,Cl, 6,M[ 4]);
    _ROUND_R2(Dr,Er,Ar,Br,Cr,13,M[11]);
    _ROUND_L2(Cl,Dl,El,Al,Bl, 8,M[13]);
    _ROUND_R2(Cr,Dr,Er,Ar,Br,15,M[ 3]);
    _ROUND_L2(Bl,Cl,Dl,El,Al,13,M[ 1]);
    _ROUND_R2(Br,Cr,Dr,Er,Ar, 7,M[ 7]);
    _ROUND_L2(Al,Bl,Cl,Dl,El,11,M[10]);
    _ROUND_R2(Ar,Br,Cr,Dr,Er,12,M[ 0]);
    _ROUND_L2(El,Al,Bl,Cl,Dl, 9,M[ 6]);
    _ROUND_R2(Er,Ar,Br,Cr,Dr, 8,M[13]);
    _ROUND_L2(Dl,El,Al,Bl,Cl, 7,M[15]);
    _ROUND_R2(Dr,Er,Ar,Br,Cr, 9,M[ 5]);
    _ROUND_L2(Cl,Dl,El,Al,Bl,15,M[ 3]);
    _ROUND_R2(Cr,Dr,Er,Ar,Br,11,M[10]);
    _ROUND_L2(Bl,Cl,Dl,El,Al, 7,M[12]);
    _ROUND_R2(Br,Cr,Dr,Er,Ar, 7,M[14]);
    _ROUND_L2(Al,Bl,Cl,Dl,El,12,M[ 0]);
    _ROUND_R2(Ar,Br,Cr,Dr,Er, 7,M[15]);
    _ROUND_L2(El,Al,Bl,Cl,Dl,15,M[ 9]);
    _ROUND_R2(Er,Ar,Br,Cr,Dr,12,M[ 8]);
    _ROUND_L2(Dl,El,Al,Bl,Cl, 9,M[ 5]);
    _ROUND_R2(Dr,Er,Ar,Br,Cr, 7,M[12]);
    _ROUND_L2(Cl,Dl,El,Al,Bl,11,M[ 2]);
    _ROUND_R2(Cr,Dr,Er,Ar,Br, 6,M[ 4]);
    _ROUND_L2(Bl,Cl,Dl,El,Al, 7,M[14]);
    _ROUND_R2(Br,Cr,Dr,Er,Ar,15,M[ 9]);
    _ROUND_L2(Al,Bl,Cl,Dl,El,13,M[11]);
    _ROUND_R2(Ar,Br,Cr,Dr,Er,13,M[ 1]);
    _ROUND_L2(El,Al,Bl,Cl,Dl,12,M[ 8]);
    _ROUND_R2(Er,Ar,Br,Cr,Dr,11,M[ 2]);
    // round 3
    _ROUND_L3(Dl,El,Al,Bl,Cl,11,M[ 3]);
    _ROUND_R3(Dr,Er,Ar,Br,Cr, 9,M[15]);
    _ROUND_L3(Cl,Dl,El,Al,Bl,13,M[10]);
    _ROUND_R3(Cr,Dr,Er,Ar,Br, 7,M[ 5]);
    _ROUND_L3(Bl,Cl,Dl,El,Al, 6,M[14]);
    _ROUND_R3(Br,Cr,Dr,Er,Ar,15,M[ 1]);
    _ROUND_L3(Al,Bl,Cl,Dl,El, 7,M[ 4]);
    _ROUND_R3(Ar,Br,Cr,Dr,Er,11,M[ 3]);
    _ROUND_L3(El,Al,Bl,Cl,Dl,14,M[ 9]);
    _ROUND_R3(Er,Ar,Br,Cr,Dr, 8,M[ 7]);
    _ROUND_L3(Dl,El,Al,Bl,Cl, 9,M[15]);
    _ROUND_R3(Dr,Er,Ar,Br,Cr, 6,M[14]);
    _ROUND_L3(Cl,Dl,El,Al,Bl,13,M[ 8]);
    _ROUND_R3(Cr,Dr,Er,Ar,Br, 6,M[ 6]);
    _ROUND_L3(Bl,Cl,Dl,El,Al,15,M[ 1]);
    _ROUND_R3(Br,Cr,Dr,Er,Ar,14,M[ 9]);
    _ROUND_L3(Al,Bl,Cl,Dl,El,14,M[ 2]);
    _ROUND_R3(Ar,Br,Cr,Dr,Er,12,M[11]);
    _ROUND_L3(El,Al,Bl,Cl,Dl, 8,M[ 7]);
    _ROUND_R3(Er,Ar,Br,Cr,Dr,13,M[ 8]);
    _ROUND_L3(Dl,El,Al,Bl,Cl,13,M[ 0]);
    _ROUND_R3(Dr,Er,Ar,Br,Cr, 5,M[12]);
    _ROUND_L3(Cl,Dl,El,Al,Bl, 6,M[ 6]);
    _ROUND_R3(Cr,Dr,Er,Ar,Br,14,M[ 2]);
    _ROUND_L3(Bl,Cl,Dl,El,Al, 5,M[13]);
    _ROUND_R3(Br,Cr,Dr,Er,Ar,13,M[10]);
    _ROUND_L3(Al,Bl,Cl,Dl,El,12,M[11]);
    _ROUND_R3(Ar,Br,Cr,Dr,Er,13,M[ 0]);
    _ROUND_L3(El,Al,Bl,Cl,Dl, 7,M[ 5]);
    _ROUND_R3(Er,Ar,Br,Cr,Dr, 7,M[ 4]);
    _ROUND_L3(Dl,El,Al,Bl,Cl, 5,M[12]);
    _ROUND_R3(Dr,Er,Ar,Br,Cr, 5,M[13]);
    // round 4
    _ROUND_L4(Cl,Dl,El,Al,Bl,11,M[ 1]);
    _ROUND_R4(Cr,Dr,Er,Ar,Br,15,M[ 8]);
    _ROUND_L4(Bl,Cl,Dl,El,Al,12,M[ 9]);
    _ROUND_R4(Br,Cr,Dr,Er,Ar, 5,M[ 6]);
    _ROUND_L4(Al,Bl,Cl,Dl,El,14,M[11]);
    _ROUND_R4(Ar,Br,Cr,Dr,Er, 8,M[ 4]);
    _ROUND_L4(El,Al,Bl,Cl,Dl,15,M[10]);
    _ROUND_R4(Er,Ar,Br,Cr,Dr,11,M[ 1]);
    _ROUND_L4(Dl,El,Al,Bl,Cl,14,M[ 0]);
    _ROUND_R4(Dr,Er,Ar,Br,Cr,14,M[ 3]);
    _ROUND_L4(Cl,Dl,El,Al,Bl,15,M[ 8]);
    _ROUND_R4(Cr,Dr,Er,Ar,Br,14,M[11]);
    _ROUND_L4(Bl,Cl,Dl,El,Al, 9,M[12]);
    _ROUND_R4(Br,Cr,Dr,Er,Ar, 6,M[15]);
    _ROUND_L4(Al,Bl,Cl,Dl,El, 8,M[ 4]);
    _ROUND_R4(Ar,Br,Cr,Dr,Er,14,M[ 0]);
    _ROUND_L4(El,Al,Bl,Cl,Dl, 9,M[13]);
    _ROUND_R4(Er,Ar,Br,Cr,Dr, 6,M[ 5]);
    _ROUND_L4(Dl,El,Al,Bl,Cl,14,M[ 3]);
    _ROUND_R4(Dr,Er,Ar,Br,Cr, 9,M[12]);
    _ROUND_L4(Cl,Dl,El,Al,Bl, 5,M[ 7]);
    _ROUND_R4(Cr,Dr,Er,Ar,Br,12,M[ 2]);
    _ROUND_L4(Bl,Cl,Dl,El,Al, 6,M[15]);
    _ROUND_R4(Br,Cr,Dr,Er,Ar, 9,M[13]);
    _ROUND_L4(Al,Bl,Cl,Dl,El, 8,M[14]);
    _ROUND_R4(Ar,Br,Cr,Dr,Er,12,M[ 9]);
    _ROUND_L4(El,Al,Bl,Cl,Dl, 6,M[ 5]);
    _ROUND_R4(Er,Ar,Br,Cr,Dr, 5,M[ 7]);
    _ROUND_L4(Dl,El,Al,Bl,Cl, 5,M[ 6]);
    _ROUND_R4(Dr,Er,Ar,Br,Cr,15,M[10]);
    _ROUND_L4(Cl,Dl,El,Al,Bl,12,M[ 2]);
    _ROUND_R4(Cr,Dr,Er,Ar,Br, 8,M[14]);
    // round 5
    _ROUND_L5(Bl,Cl,Dl,El,Al, 9,M[ 4]);
    _ROUND_R5(Br,Cr,Dr,Er,Ar, 8,M[12]);
    _ROUND_L5(Al,Bl,Cl,Dl,El,15,M[ 0]);
    _ROUND_R5(Ar,Br,Cr,Dr,Er, 5,M[15]);
    _ROUND_L5(El,Al,Bl,Cl,Dl, 5,M[ 5]);
    _ROUND_R5(Er,Ar,Br,Cr,Dr,12,M[10]);
    _ROUND_L5(Dl,El,Al,Bl,Cl,11,M[ 9]);
    _ROUND_R5(Dr,Er,Ar,Br,Cr, 9,M[ 4]);
    _ROUND_L5(Cl,Dl,El,Al,Bl, 6,M[ 7]);
    _ROUND_R5(Cr,Dr,Er,Ar,Br,12,M[ 1]);
    _ROUND_L5(Bl,Cl,Dl,El,Al, 8,M[12]);
    _ROUND_R5(Br,Cr,Dr,Er,Ar, 5,M[ 5]);
    _ROUND_L5(Al,Bl,Cl,Dl,El,13,M[ 2]);
    _ROUND_R5(Ar,Br,Cr,Dr,Er,14,M[ 8]);
    _ROUND_L5(El,Al,Bl,Cl,Dl,12,M[10]);
    _ROUND_R5(Er,Ar,Br,Cr,Dr, 6,M[ 7]);
    _ROUND_L5(Dl,El,Al,Bl,Cl, 5,M[14]);
    _ROUND_R5(Dr,Er,Ar,Br,Cr, 8,M[ 6]);
    _ROUND_L5(Cl,Dl,El,Al,Bl,12,M[ 1]);
    _ROUND_R5(Cr,Dr,Er,Ar,Br,13,M[ 2]);
    _ROUND_L5(Bl,Cl,Dl,El,Al,13,M[ 3]);
    _ROUND_R5(Br,Cr,Dr,Er,Ar, 6,M[13]);
    _ROUND_L5(Al,Bl,Cl,Dl,El,14,M[ 8]);
    _ROUND_R5(Ar,Br,Cr,Dr,Er, 5,M[14]);
    _ROUND_L5(El,Al,Bl,Cl,Dl,11,M[11]);
    _ROUND_R5(Er,Ar,Br,Cr,Dr,15,M[ 0]);
    _ROUND_L5(Dl,El,Al,Bl,Cl, 8,M[ 6]);
    _ROUND_R5(Dr,Er,Ar,Br,Cr,13,M[ 3]);
    _ROUND_L5(Cl,Dl,El,Al,Bl, 5,M[15]);
    _ROUND_R5(Cr,Dr,Er,Ar,Br,11,M[ 9]);
    _ROUND_L5(Bl,Cl,Dl,El,Al, 6,M[13]);
    _ROUND_R5(Br,Cr,Dr,Er,Ar,11,M[11]);
    // update cumulative hash
    t = hash[1] + Cl + Dr;
    hash[1] = hash[2] + Dl + Er;
    hash[2] = hash[3] + El + Ar;
    hash[3] = hash[4] + Al + Br;
    hash[4] = hash[0] + Bl + Cr;
    hash[0] = t;
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
