#include "hash.h"
#include "_util.h"

#include <byteswap.h>
#include <stdint.h>
#include <string.h>

// initial values
#define HASH_SHA1_H0 0x67452301
#define HASH_SHA1_H1 0xEFCDAB89
#define HASH_SHA1_H2 0x98BADCFE
#define HASH_SHA1_H3 0x10325476
#define HASH_SHA1_H4 0xC3D2E1F0
// round functions
#define _F1(B,C,D) ((B & C) | ((~B) & D))
#define _F2(B,C,D) (B ^ C ^ D)
#define _F3(B,C,D) ((B & C) | (B & D) | (C & D))
#define _F4(B,C,D) (B ^ C ^ D)
#define _ROTL(n,bits) (((n) << bits) | ((n) >> (32 - bits)))
// perform a round
// w = message word, k = constant
#define _FF1(A,B,C,D,E,w) (E += _F1(B,C,D) + _ROTL(A,5) + w + 0x5A827999, B = _ROTL(B,30))
#define _FF2(A,B,C,D,E,w) (E += _F2(B,C,D) + _ROTL(A,5) + w + 0x6ED9EBA1, B = _ROTL(B,30))
#define _FF3(A,B,C,D,E,w) (E += _F3(B,C,D) + _ROTL(A,5) + w + 0x8F1BBCDC, B = _ROTL(B,30))
#define _FF4(A,B,C,D,E,w) (E += _F4(B,C,D) + _ROTL(A,5) + w + 0xCA62C1D6, B = _ROTL(B,30))

// M (the block) must have length 16
void hash_sha1_block(uint32_t * restrict hash, const uint32_t * restrict M)
{
    uint32_t A = hash[0], B = hash[1], C = hash[2], D = hash[3], E = hash[4];
    // message schedule
    uint32_t w[80];
    size_t i;
    for (i = 0; i < 16; ++i) // swap to little endian (sha1 is big endian)
        w[i] = bswap_32(M[i]);
    for (; i < 80; ++i)
        w[i] = _ROTL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    // round 1
    _FF1(A,B,C,D,E,w[ 0]);
    _FF1(E,A,B,C,D,w[ 1]);
    _FF1(D,E,A,B,C,w[ 2]);
    _FF1(C,D,E,A,B,w[ 3]);
    _FF1(B,C,D,E,A,w[ 4]);
    _FF1(A,B,C,D,E,w[ 5]);
    _FF1(E,A,B,C,D,w[ 6]);
    _FF1(D,E,A,B,C,w[ 7]);
    _FF1(C,D,E,A,B,w[ 8]);
    _FF1(B,C,D,E,A,w[ 9]);
    _FF1(A,B,C,D,E,w[10]);
    _FF1(E,A,B,C,D,w[11]);
    _FF1(D,E,A,B,C,w[12]);
    _FF1(C,D,E,A,B,w[13]);
    _FF1(B,C,D,E,A,w[14]);
    _FF1(A,B,C,D,E,w[15]);
    _FF1(E,A,B,C,D,w[16]);
    _FF1(D,E,A,B,C,w[17]);
    _FF1(C,D,E,A,B,w[18]);
    _FF1(B,C,D,E,A,w[19]);
    // round 2
    _FF2(A,B,C,D,E,w[20]);
    _FF2(E,A,B,C,D,w[21]);
    _FF2(D,E,A,B,C,w[22]);
    _FF2(C,D,E,A,B,w[23]);
    _FF2(B,C,D,E,A,w[24]);
    _FF2(A,B,C,D,E,w[25]);
    _FF2(E,A,B,C,D,w[26]);
    _FF2(D,E,A,B,C,w[27]);
    _FF2(C,D,E,A,B,w[28]);
    _FF2(B,C,D,E,A,w[29]);
    _FF2(A,B,C,D,E,w[30]);
    _FF2(E,A,B,C,D,w[31]);
    _FF2(D,E,A,B,C,w[32]);
    _FF2(C,D,E,A,B,w[33]);
    _FF2(B,C,D,E,A,w[34]);
    _FF2(A,B,C,D,E,w[35]);
    _FF2(E,A,B,C,D,w[36]);
    _FF2(D,E,A,B,C,w[37]);
    _FF2(C,D,E,A,B,w[38]);
    _FF2(B,C,D,E,A,w[39]);
    // round 3
    _FF3(A,B,C,D,E,w[40]);
    _FF3(E,A,B,C,D,w[41]);
    _FF3(D,E,A,B,C,w[42]);
    _FF3(C,D,E,A,B,w[43]);
    _FF3(B,C,D,E,A,w[44]);
    _FF3(A,B,C,D,E,w[45]);
    _FF3(E,A,B,C,D,w[46]);
    _FF3(D,E,A,B,C,w[47]);
    _FF3(C,D,E,A,B,w[48]);
    _FF3(B,C,D,E,A,w[49]);
    _FF3(A,B,C,D,E,w[50]);
    _FF3(E,A,B,C,D,w[51]);
    _FF3(D,E,A,B,C,w[52]);
    _FF3(C,D,E,A,B,w[53]);
    _FF3(B,C,D,E,A,w[54]);
    _FF3(A,B,C,D,E,w[55]);
    _FF3(E,A,B,C,D,w[56]);
    _FF3(D,E,A,B,C,w[57]);
    _FF3(C,D,E,A,B,w[58]);
    _FF3(B,C,D,E,A,w[59]);
    // round 4
    _FF4(A,B,C,D,E,w[60]);
    _FF4(E,A,B,C,D,w[61]);
    _FF4(D,E,A,B,C,w[62]);
    _FF4(C,D,E,A,B,w[63]);
    _FF4(B,C,D,E,A,w[64]);
    _FF4(A,B,C,D,E,w[65]);
    _FF4(E,A,B,C,D,w[66]);
    _FF4(D,E,A,B,C,w[67]);
    _FF4(C,D,E,A,B,w[68]);
    _FF4(B,C,D,E,A,w[69]);
    _FF4(A,B,C,D,E,w[70]);
    _FF4(E,A,B,C,D,w[71]);
    _FF4(D,E,A,B,C,w[72]);
    _FF4(C,D,E,A,B,w[73]);
    _FF4(B,C,D,E,A,w[74]);
    _FF4(A,B,C,D,E,w[75]);
    _FF4(E,A,B,C,D,w[76]);
    _FF4(D,E,A,B,C,w[77]);
    _FF4(C,D,E,A,B,w[78]);
    _FF4(B,C,D,E,A,w[79]);
    // add to cumulative hash
    hash[0] += A, hash[1] += B, hash[2] += C, hash[3] += D, hash[4] += E;
}

void hash_sha1_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash)
{
    const uint8_t *end = array + len;
    const uint8_t *block = array;
    uint32_t h[5] = {HASH_SHA1_H0,HASH_SHA1_H1,HASH_SHA1_H2,HASH_SHA1_H3,HASH_SHA1_H4};
    while (block + 64 <= end)
    {
        hash_sha1_block(h,(uint32_t*)block);
        block += 64;
    }
    // padding
    uint8_t buf[128];
    size_t buf_len = 0;
    size_t block_len = end - block;
    _pad1(buf,&buf_len,block,block_len,bswap_64(len<<3)); // big endian length
    // hash last blocks
    hash_sha1_block(h,(uint32_t*)buf);
    if (buf_len == 128)
        hash_sha1_block(h,(uint32_t*)buf+16);
    // change to little endian
    h[0] = bswap_32(h[0]);
    h[1] = bswap_32(h[1]);
    h[2] = bswap_32(h[2]);
    h[3] = bswap_32(h[3]);
    h[4] = bswap_32(h[4]);
    memcpy(hash,h,20);
}
