#include "hash.h"
#include "_util.h"

#include <stdint.h>
#include <string.h>

// initial values
#define HASH_MD4_A0 0x67452301
#define HASH_MD4_B0 0xefcdab89
#define HASH_MD4_C0 0x98badcfe
#define HASH_MD4_D0 0x10325476
// nonlinear round functions
#define _F(B,C,D) ((B & C) | ((~B) & D))
#define _G(B,C,D) ((B & C) | (B & D) | (C & D))
#define _H(B,C,D) (B ^ C ^ D)
#define _ROTL(n,bits) ((n << bits) | (n >> (32 - bits)))
// perform a round
// x = message word, s = shift, k = constant
#define _FF(A,B,C,D,x,s) (A = _ROTL((A + _F(B,C,D) + x), s))
#define _GG(A,B,C,D,x,s) (A = _ROTL((A + _G(B,C,D) + x + 0x5A827999), s))
#define _HH(A,B,C,D,x,s) (A = _ROTL((A + _H(B,C,D) + x + 0x6ED9EBA1), s))

// rounds
// A B C D -> D A* B C (where A is modified by the round function)
// A B C D -> D A B C -> C D A B -> B C D A -> ...
// round | shifts    | [0,15] -> message index
// 1     | 3 7 11 19 | i -> i
// 2     | 3 5 9 13  | i -> 4*(i%4)+(i//4)
// 3     | 3 9 11 15 | i ->

// M (the block) must have length 16
void hash_md4_block(uint32_t * restrict hash, const uint32_t * restrict M)
{
    uint32_t A = hash[0], B = hash[1], C = hash[2], D = hash[3];
    // round 1
    _FF(A,B,C,D,M[ 0], 3);
    _FF(D,A,B,C,M[ 1], 7);
    _FF(C,D,A,B,M[ 2],11);
    _FF(B,C,D,A,M[ 3],19);
    _FF(A,B,C,D,M[ 4], 3);
    _FF(D,A,B,C,M[ 5], 7);
    _FF(C,D,A,B,M[ 6],11);
    _FF(B,C,D,A,M[ 7],19);
    _FF(A,B,C,D,M[ 8], 3);
    _FF(D,A,B,C,M[ 9], 7);
    _FF(C,D,A,B,M[10],11);
    _FF(B,C,D,A,M[11],19);
    _FF(A,B,C,D,M[12], 3);
    _FF(D,A,B,C,M[13], 7);
    _FF(C,D,A,B,M[14],11);
    _FF(B,C,D,A,M[15],19);
    // round 2
    _GG(A,B,C,D,M[ 0], 3);
    _GG(D,A,B,C,M[ 4], 5);
    _GG(C,D,A,B,M[ 8], 9);
    _GG(B,C,D,A,M[12],13);
    _GG(A,B,C,D,M[ 1], 3);
    _GG(D,A,B,C,M[ 5], 5);
    _GG(C,D,A,B,M[ 9], 9);
    _GG(B,C,D,A,M[13],13);
    _GG(A,B,C,D,M[ 2], 3);
    _GG(D,A,B,C,M[ 6], 5);
    _GG(C,D,A,B,M[10], 9);
    _GG(B,C,D,A,M[14],13);
    _GG(A,B,C,D,M[ 3], 3);
    _GG(D,A,B,C,M[ 7], 5);
    _GG(C,D,A,B,M[11], 9);
    _GG(B,C,D,A,M[15],13);
    // round 3
    _HH(A,B,C,D,M[ 0], 3);
    _HH(D,A,B,C,M[ 8], 9);
    _HH(C,D,A,B,M[ 4],11);
    _HH(B,C,D,A,M[12],15);
    _HH(A,B,C,D,M[ 2], 3);
    _HH(D,A,B,C,M[10], 9);
    _HH(C,D,A,B,M[ 6],11);
    _HH(B,C,D,A,M[14],15);
    _HH(A,B,C,D,M[ 1], 3);
    _HH(D,A,B,C,M[ 9], 9);
    _HH(C,D,A,B,M[ 5],11);
    _HH(B,C,D,A,M[13],15);
    _HH(A,B,C,D,M[ 3], 3);
    _HH(D,A,B,C,M[11], 9);
    _HH(C,D,A,B,M[ 7],11);
    _HH(B,C,D,A,M[15],15);
    // add to cumulative hash
    hash[0] += A, hash[1] += B, hash[2] += C, hash[3] += D;
}

// hash must be a 16 byte array
void hash_md4_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash)
{
    const uint8_t *end = array + len;
    const uint8_t *block = array;
    uint32_t h[4] = {HASH_MD4_A0,HASH_MD4_B0,HASH_MD4_C0,HASH_MD4_D0};
    while (block + 64 <= end)
    {
        hash_md4_block(h,(uint32_t*)block);
        block += 64;
    }
    // padding
    uint8_t buf[128];
    size_t buf_len = 0;
    size_t block_len = end - block;
    _pad1(buf,&buf_len,block,block_len,len<<3);
    // hash last block(s)
    hash_md4_block(h,(uint32_t*)buf);
    if (buf_len == 128)
        hash_md4_block(h,(uint32_t*)buf+16);
    memcpy(hash,h,16);
}
