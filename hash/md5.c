#include "hash.h"
#include "_util.h"

#include <stdint.h>
#include <string.h>

// initial values
const uint32_t _MD5_INIT[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
// round functions
#define _F(B,C,D) ((B & C) | ((~B) & D))
#define _G(B,C,D) ((B & D) | (C & (~D)))
#define _H(B,C,D) (B ^ C ^ D)
#define _I(B,C,D) (C ^ (B | (~D)))
#define _ROTL(n,bits) ((n << bits) | (n >> (32 - bits)))
// perform a round
// x = message word, s = shift, k = constant
#define _FF(A,B,C,D,x,s,k) (A = B + _ROTL((A + _F(B,C,D) + x + k), s))
#define _GG(A,B,C,D,x,s,k) (A = B + _ROTL((A + _G(B,C,D) + x + k), s))
#define _HH(A,B,C,D,x,s,k) (A = B + _ROTL((A + _H(B,C,D) + x + k), s))
#define _II(A,B,C,D,x,s,k) (A = B + _ROTL((A + _I(B,C,D) + x + k), s))

// rounds
// A B C D -> D A* B C (where A is modified by the round function)
// A B C D -> D A B C -> C D A B -> B C D A -> ...
// round | shifts     | [0,15] -> message index
// 1     | 7 12 17 22 | i -> i
// 2     | 5 9 14 20  | i -> (5*i+1) mod 16
// 3     | 4 11 16 23 | i -> (3*i+5) mod 16
// 4     | 6 10 15 21 | i -> (7*i) mod 16

// M (the block) must have length 16
void hash_md5_block(uint32_t * restrict hash, const uint32_t * restrict M)
{
    uint32_t A = hash[0], B = hash[1], C = hash[2], D = hash[3];
    // round 1
    _FF(A,B,C,D,M[ 0], 7,0xd76aa478);
    _FF(D,A,B,C,M[ 1],12,0xe8c7b756);
    _FF(C,D,A,B,M[ 2],17,0x242070db);
    _FF(B,C,D,A,M[ 3],22,0xc1bdceee);
    _FF(A,B,C,D,M[ 4], 7,0xf57c0faf);
    _FF(D,A,B,C,M[ 5],12,0x4787c62a);
    _FF(C,D,A,B,M[ 6],17,0xa8304613);
    _FF(B,C,D,A,M[ 7],22,0xfd469501);
    _FF(A,B,C,D,M[ 8], 7,0x698098d8);
    _FF(D,A,B,C,M[ 9],12,0x8b44f7af);
    _FF(C,D,A,B,M[10],17,0xffff5bb1);
    _FF(B,C,D,A,M[11],22,0x895cd7be);
    _FF(A,B,C,D,M[12], 7,0x6b901122);
    _FF(D,A,B,C,M[13],12,0xfd987193);
    _FF(C,D,A,B,M[14],17,0xa679438e);
    _FF(B,C,D,A,M[15],22,0x49b40821);
    // round 2
    _GG(A,B,C,D,M[ 1], 5,0xf61e2562);
    _GG(D,A,B,C,M[ 6], 9,0xc040b340);
    _GG(C,D,A,B,M[11],14,0x265e5a51);
    _GG(B,C,D,A,M[ 0],20,0xe9b6c7aa);
    _GG(A,B,C,D,M[ 5], 5,0xd62f105d);
    _GG(D,A,B,C,M[10], 9,0x02441453);
    _GG(C,D,A,B,M[15],14,0xd8a1e681);
    _GG(B,C,D,A,M[ 4],20,0xe7d3fbc8);
    _GG(A,B,C,D,M[ 9], 5,0x21e1cde6);
    _GG(D,A,B,C,M[14], 9,0xc33707d6);
    _GG(C,D,A,B,M[ 3],14,0xf4d50d87);
    _GG(B,C,D,A,M[ 8],20,0x455a14ed);
    _GG(A,B,C,D,M[13], 5,0xa9e3e905);
    _GG(D,A,B,C,M[ 2], 9,0xfcefa3f8);
    _GG(C,D,A,B,M[ 7],14,0x676f02d9);
    _GG(B,C,D,A,M[12],20,0x8d2a4c8a);
    // round 3
    _HH(A,B,C,D,M[ 5], 4,0xfffa3942);
    _HH(D,A,B,C,M[ 8],11,0x8771f681);
    _HH(C,D,A,B,M[11],16,0x6d9d6122);
    _HH(B,C,D,A,M[14],23,0xfde5380c);
    _HH(A,B,C,D,M[ 1], 4,0xa4beea44);
    _HH(D,A,B,C,M[ 4],11,0x4bdecfa9);
    _HH(C,D,A,B,M[ 7],16,0xf6bb4b60);
    _HH(B,C,D,A,M[10],23,0xbebfbc70);
    _HH(A,B,C,D,M[13], 4,0x289b7ec6);
    _HH(D,A,B,C,M[ 0],11,0xeaa127fa);
    _HH(C,D,A,B,M[ 3],16,0xd4ef3085);
    _HH(B,C,D,A,M[ 6],23,0x04881d05);
    _HH(A,B,C,D,M[ 9], 4,0xd9d4d039);
    _HH(D,A,B,C,M[12],11,0xe6db99e5);
    _HH(C,D,A,B,M[15],16,0x1fa27cf8);
    _HH(B,C,D,A,M[ 2],23,0xc4ac5665);
    // round 4
    _II(A,B,C,D,M[ 0], 6,0xf4292244);
    _II(D,A,B,C,M[ 7],10,0x432aff97);
    _II(C,D,A,B,M[14],15,0xab9423a7);
    _II(B,C,D,A,M[ 5],21,0xfc93a039);
    _II(A,B,C,D,M[12], 6,0x655b59c3);
    _II(D,A,B,C,M[ 3],10,0x8f0ccc92);
    _II(C,D,A,B,M[10],15,0xffeff47d);
    _II(B,C,D,A,M[ 1],21,0x85845dd1);
    _II(A,B,C,D,M[ 8], 6,0x6fa87e4f);
    _II(D,A,B,C,M[15],10,0xfe2ce6e0);
    _II(C,D,A,B,M[ 6],15,0xa3014314);
    _II(B,C,D,A,M[13],21,0x4e0811a1);
    _II(A,B,C,D,M[ 4], 6,0xf7537e82);
    _II(D,A,B,C,M[11],10,0xbd3af235);
    _II(C,D,A,B,M[ 2],15,0x2ad7d2bb);
    _II(B,C,D,A,M[ 9],21,0xeb86d391);
    // add to cumulative hash
    hash[0] += A, hash[1] += B, hash[2] += C, hash[3] += D;
}

// hash must be a 16 byte array
void hash_md5_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash)
{
    const uint8_t *end = array + len;
    const uint8_t *block = array;
    uint32_t h[4];
    memcpy(h,_MD5_INIT,16);
    while (block + 64 <= end)
    {
        hash_md5_block(h,(uint32_t*)block);
        block += 64;
    }
    // padding
    uint8_t buf[128];
    size_t buf_len = 0;
    size_t block_len = end - block;
    _pad1(buf,&buf_len,block,block_len,len<<3);
    // hash last block(s)
    hash_md5_block(h,(uint32_t*)buf);
    if (buf_len == 128)
        hash_md5_block(h,(uint32_t*)buf+16);
    memcpy(hash,h,16);
}
