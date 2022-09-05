#include "hash.h"
#include "_util.h"

#include <byteswap.h>
#include <stdint.h>
#include <string.h>

// initial values
const uint32_t _SHA256_INIT[8] =
{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
const uint32_t _SHA224_INIT[8] =
{
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};
const uint64_t _SHA512_INIT[8] =
{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};
const uint64_t _SHA384_INIT[8] =
{
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};
// round functions
#define _ROTR32(n,bits) ((n >> bits) | (n << (32 - bits)))
#define _RS1_32(e) (_ROTR32(e,6) ^ _ROTR32(e,11) ^ _ROTR32(e,25))
#define _RCH(e,f,g) ((e & f) ^ ((~e) & g))
#define _RT1_32(e,f,g,h,K,W) (t1 = h + _RS1_32(e) + _RCH(e,f,g) + K + W)
#define _RS0_32(a) (_ROTR32(a,2) ^ _ROTR32(a,13) ^ _ROTR32(a,22))
#define _RMAJ(a,b,c) ((a & b) ^ (a & c) ^ (b & c))
#define _RT2_32(a,b,c) (t2 = _RS0_32(a) + _RMAJ(a,b,c))
#define _ROUND32(a,b,c,d,e,f,g,h,W,K) (_RT1_32(e,f,g,h,K,W), _RT2_32(a,b,c), d += t1, h = t1 + t2)
#define _ROTR64(n,bits) ((n >> bits) | (n << (64 - bits)))
#define _RS1_64(e) (_ROTR64(e,14) ^ _ROTR64(e,18) ^ _ROTR64(e,41))
#define _RT1_64(e,f,g,h,K,W) (t1 = h + _RS1_64(e) + _RCH(e,f,g) + K + W)
#define _RS0_64(a) (_ROTR64(a,28) ^ _ROTR64(a,34) ^ _ROTR64(a,39))
#define _RT2_64(a,b,c) (t2 = _RS0_64(a) + _RMAJ(a,b,c))
#define _ROUND64(a,b,c,d,e,f,g,h,W,K) (_RT1_64(e,f,g,h,K,W), _RT2_64(a,b,c), d += t1, h = t1 + t2)
// message schedule macros
#define _SCH0_32 (_ROTR32(w[i-15],7) ^ _ROTR32(w[i-15],18) ^ (w[i-15] >> 3))
#define _SCH1_32 (_ROTR32(w[i-2],17) ^ _ROTR32(w[i-2],19) ^ (w[i-2] >> 10))
#define _SCH0_64 (_ROTR64(w[i-15],1) ^ _ROTR64(w[i-15],8) ^ (w[i-15] >> 7))
#define _SCH1_64 (_ROTR64(w[i-2],19) ^ _ROTR64(w[i-2],61) ^ (w[i-2] >> 6))

// M (the block) must have length 16
void hash_sha256_block(uint32_t * restrict hash, const uint32_t * restrict M)
{
    uint32_t a = hash[0], b = hash[1], c = hash[2], d = hash[3], e = hash[4], f = hash[5], g = hash[6], h = hash[7];
    uint32_t w[64];
    size_t i;
    for (i = 0; i < 16; ++i)
        w[i] = bswap_32(M[i]);
    for (; i < 64; ++i)
        w[i] = w[i-16] + _SCH0_32 + w[i-7] + _SCH1_32;
    uint32_t t1,t2;
    // rounds
    _ROUND32(a,b,c,d,e,f,g,h,w[ 0],0x428a2f98);
    _ROUND32(h,a,b,c,d,e,f,g,w[ 1],0x71374491);
    _ROUND32(g,h,a,b,c,d,e,f,w[ 2],0xb5c0fbcf);
    _ROUND32(f,g,h,a,b,c,d,e,w[ 3],0xe9b5dba5);
    _ROUND32(e,f,g,h,a,b,c,d,w[ 4],0x3956c25b);
    _ROUND32(d,e,f,g,h,a,b,c,w[ 5],0x59f111f1);
    _ROUND32(c,d,e,f,g,h,a,b,w[ 6],0x923f82a4);
    _ROUND32(b,c,d,e,f,g,h,a,w[ 7],0xab1c5ed5);
    _ROUND32(a,b,c,d,e,f,g,h,w[ 8],0xd807aa98);
    _ROUND32(h,a,b,c,d,e,f,g,w[ 9],0x12835b01);
    _ROUND32(g,h,a,b,c,d,e,f,w[10],0x243185be);
    _ROUND32(f,g,h,a,b,c,d,e,w[11],0x550c7dc3);
    _ROUND32(e,f,g,h,a,b,c,d,w[12],0x72be5d74);
    _ROUND32(d,e,f,g,h,a,b,c,w[13],0x80deb1fe);
    _ROUND32(c,d,e,f,g,h,a,b,w[14],0x9bdc06a7);
    _ROUND32(b,c,d,e,f,g,h,a,w[15],0xc19bf174);
    _ROUND32(a,b,c,d,e,f,g,h,w[16],0xe49b69c1);
    _ROUND32(h,a,b,c,d,e,f,g,w[17],0xefbe4786);
    _ROUND32(g,h,a,b,c,d,e,f,w[18],0x0fc19dc6);
    _ROUND32(f,g,h,a,b,c,d,e,w[19],0x240ca1cc);
    _ROUND32(e,f,g,h,a,b,c,d,w[20],0x2de92c6f);
    _ROUND32(d,e,f,g,h,a,b,c,w[21],0x4a7484aa);
    _ROUND32(c,d,e,f,g,h,a,b,w[22],0x5cb0a9dc);
    _ROUND32(b,c,d,e,f,g,h,a,w[23],0x76f988da);
    _ROUND32(a,b,c,d,e,f,g,h,w[24],0x983e5152);
    _ROUND32(h,a,b,c,d,e,f,g,w[25],0xa831c66d);
    _ROUND32(g,h,a,b,c,d,e,f,w[26],0xb00327c8);
    _ROUND32(f,g,h,a,b,c,d,e,w[27],0xbf597fc7);
    _ROUND32(e,f,g,h,a,b,c,d,w[28],0xc6e00bf3);
    _ROUND32(d,e,f,g,h,a,b,c,w[29],0xd5a79147);
    _ROUND32(c,d,e,f,g,h,a,b,w[30],0x06ca6351);
    _ROUND32(b,c,d,e,f,g,h,a,w[31],0x14292967);
    _ROUND32(a,b,c,d,e,f,g,h,w[32],0x27b70a85);
    _ROUND32(h,a,b,c,d,e,f,g,w[33],0x2e1b2138);
    _ROUND32(g,h,a,b,c,d,e,f,w[34],0x4d2c6dfc);
    _ROUND32(f,g,h,a,b,c,d,e,w[35],0x53380d13);
    _ROUND32(e,f,g,h,a,b,c,d,w[36],0x650a7354);
    _ROUND32(d,e,f,g,h,a,b,c,w[37],0x766a0abb);
    _ROUND32(c,d,e,f,g,h,a,b,w[38],0x81c2c92e);
    _ROUND32(b,c,d,e,f,g,h,a,w[39],0x92722c85);
    _ROUND32(a,b,c,d,e,f,g,h,w[40],0xa2bfe8a1);
    _ROUND32(h,a,b,c,d,e,f,g,w[41],0xa81a664b);
    _ROUND32(g,h,a,b,c,d,e,f,w[42],0xc24b8b70);
    _ROUND32(f,g,h,a,b,c,d,e,w[43],0xc76c51a3);
    _ROUND32(e,f,g,h,a,b,c,d,w[44],0xd192e819);
    _ROUND32(d,e,f,g,h,a,b,c,w[45],0xd6990624);
    _ROUND32(c,d,e,f,g,h,a,b,w[46],0xf40e3585);
    _ROUND32(b,c,d,e,f,g,h,a,w[47],0x106aa070);
    _ROUND32(a,b,c,d,e,f,g,h,w[48],0x19a4c116);
    _ROUND32(h,a,b,c,d,e,f,g,w[49],0x1e376c08);
    _ROUND32(g,h,a,b,c,d,e,f,w[50],0x2748774c);
    _ROUND32(f,g,h,a,b,c,d,e,w[51],0x34b0bcb5);
    _ROUND32(e,f,g,h,a,b,c,d,w[52],0x391c0cb3);
    _ROUND32(d,e,f,g,h,a,b,c,w[53],0x4ed8aa4a);
    _ROUND32(c,d,e,f,g,h,a,b,w[54],0x5b9cca4f);
    _ROUND32(b,c,d,e,f,g,h,a,w[55],0x682e6ff3);
    _ROUND32(a,b,c,d,e,f,g,h,w[56],0x748f82ee);
    _ROUND32(h,a,b,c,d,e,f,g,w[57],0x78a5636f);
    _ROUND32(g,h,a,b,c,d,e,f,w[58],0x84c87814);
    _ROUND32(f,g,h,a,b,c,d,e,w[59],0x8cc70208);
    _ROUND32(e,f,g,h,a,b,c,d,w[60],0x90befffa);
    _ROUND32(d,e,f,g,h,a,b,c,w[61],0xa4506ceb);
    _ROUND32(c,d,e,f,g,h,a,b,w[62],0xbef9a3f7);
    _ROUND32(b,c,d,e,f,g,h,a,w[63],0xc67178f2);
    // add to cumulative hash
    hash[0] += a, hash[1] += b, hash[2] += c, hash[3] += d, hash[4] += e, hash[5] += f, hash[6] += g, hash[7] += h;
}

// M (the block) must have length 16
void hash_sha512_block(uint64_t * restrict hash, const uint64_t * restrict M)
{
    uint64_t a = hash[0], b = hash[1], c = hash[2], d = hash[3], e = hash[4], f = hash[5], g = hash[6], h = hash[7];
    uint64_t w[80];
    size_t i;
    for (i = 0; i < 16; ++i)
        w[i] = bswap_64(M[i]);
    for (; i < 80; ++i)
        w[i] = w[i-16] + _SCH0_64 + w[i-7] + _SCH1_64;
    uint64_t t1,t2;
    // rounds
    _ROUND64(a,b,c,d,e,f,g,h,w[ 0],0x428a2f98d728ae22);
    _ROUND64(h,a,b,c,d,e,f,g,w[ 1],0x7137449123ef65cd);
    _ROUND64(g,h,a,b,c,d,e,f,w[ 2],0xb5c0fbcfec4d3b2f);
    _ROUND64(f,g,h,a,b,c,d,e,w[ 3],0xe9b5dba58189dbbc);
    _ROUND64(e,f,g,h,a,b,c,d,w[ 4],0x3956c25bf348b538);
    _ROUND64(d,e,f,g,h,a,b,c,w[ 5],0x59f111f1b605d019);
    _ROUND64(c,d,e,f,g,h,a,b,w[ 6],0x923f82a4af194f9b);
    _ROUND64(b,c,d,e,f,g,h,a,w[ 7],0xab1c5ed5da6d8118);
    _ROUND64(a,b,c,d,e,f,g,h,w[ 8],0xd807aa98a3030242);
    _ROUND64(h,a,b,c,d,e,f,g,w[ 9],0x12835b0145706fbe);
    _ROUND64(g,h,a,b,c,d,e,f,w[10],0x243185be4ee4b28c);
    _ROUND64(f,g,h,a,b,c,d,e,w[11],0x550c7dc3d5ffb4e2);
    _ROUND64(e,f,g,h,a,b,c,d,w[12],0x72be5d74f27b896f);
    _ROUND64(d,e,f,g,h,a,b,c,w[13],0x80deb1fe3b1696b1);
    _ROUND64(c,d,e,f,g,h,a,b,w[14],0x9bdc06a725c71235);
    _ROUND64(b,c,d,e,f,g,h,a,w[15],0xc19bf174cf692694);
    _ROUND64(a,b,c,d,e,f,g,h,w[16],0xe49b69c19ef14ad2);
    _ROUND64(h,a,b,c,d,e,f,g,w[17],0xefbe4786384f25e3);
    _ROUND64(g,h,a,b,c,d,e,f,w[18],0x0fc19dc68b8cd5b5);
    _ROUND64(f,g,h,a,b,c,d,e,w[19],0x240ca1cc77ac9c65);
    _ROUND64(e,f,g,h,a,b,c,d,w[20],0x2de92c6f592b0275);
    _ROUND64(d,e,f,g,h,a,b,c,w[21],0x4a7484aa6ea6e483);
    _ROUND64(c,d,e,f,g,h,a,b,w[22],0x5cb0a9dcbd41fbd4);
    _ROUND64(b,c,d,e,f,g,h,a,w[23],0x76f988da831153b5);
    _ROUND64(a,b,c,d,e,f,g,h,w[24],0x983e5152ee66dfab);
    _ROUND64(h,a,b,c,d,e,f,g,w[25],0xa831c66d2db43210);
    _ROUND64(g,h,a,b,c,d,e,f,w[26],0xb00327c898fb213f);
    _ROUND64(f,g,h,a,b,c,d,e,w[27],0xbf597fc7beef0ee4);
    _ROUND64(e,f,g,h,a,b,c,d,w[28],0xc6e00bf33da88fc2);
    _ROUND64(d,e,f,g,h,a,b,c,w[29],0xd5a79147930aa725);
    _ROUND64(c,d,e,f,g,h,a,b,w[30],0x06ca6351e003826f);
    _ROUND64(b,c,d,e,f,g,h,a,w[31],0x142929670a0e6e70);
    _ROUND64(a,b,c,d,e,f,g,h,w[32],0x27b70a8546d22ffc);
    _ROUND64(h,a,b,c,d,e,f,g,w[33],0x2e1b21385c26c926);
    _ROUND64(g,h,a,b,c,d,e,f,w[34],0x4d2c6dfc5ac42aed);
    _ROUND64(f,g,h,a,b,c,d,e,w[35],0x53380d139d95b3df);
    _ROUND64(e,f,g,h,a,b,c,d,w[36],0x650a73548baf63de);
    _ROUND64(d,e,f,g,h,a,b,c,w[37],0x766a0abb3c77b2a8);
    _ROUND64(c,d,e,f,g,h,a,b,w[38],0x81c2c92e47edaee6);
    _ROUND64(b,c,d,e,f,g,h,a,w[39],0x92722c851482353b);
    _ROUND64(a,b,c,d,e,f,g,h,w[40],0xa2bfe8a14cf10364);
    _ROUND64(h,a,b,c,d,e,f,g,w[41],0xa81a664bbc423001);
    _ROUND64(g,h,a,b,c,d,e,f,w[42],0xc24b8b70d0f89791);
    _ROUND64(f,g,h,a,b,c,d,e,w[43],0xc76c51a30654be30);
    _ROUND64(e,f,g,h,a,b,c,d,w[44],0xd192e819d6ef5218);
    _ROUND64(d,e,f,g,h,a,b,c,w[45],0xd69906245565a910);
    _ROUND64(c,d,e,f,g,h,a,b,w[46],0xf40e35855771202a);
    _ROUND64(b,c,d,e,f,g,h,a,w[47],0x106aa07032bbd1b8);
    _ROUND64(a,b,c,d,e,f,g,h,w[48],0x19a4c116b8d2d0c8);
    _ROUND64(h,a,b,c,d,e,f,g,w[49],0x1e376c085141ab53);
    _ROUND64(g,h,a,b,c,d,e,f,w[50],0x2748774cdf8eeb99);
    _ROUND64(f,g,h,a,b,c,d,e,w[51],0x34b0bcb5e19b48a8);
    _ROUND64(e,f,g,h,a,b,c,d,w[52],0x391c0cb3c5c95a63);
    _ROUND64(d,e,f,g,h,a,b,c,w[53],0x4ed8aa4ae3418acb);
    _ROUND64(c,d,e,f,g,h,a,b,w[54],0x5b9cca4f7763e373);
    _ROUND64(b,c,d,e,f,g,h,a,w[55],0x682e6ff3d6b2b8a3);
    _ROUND64(a,b,c,d,e,f,g,h,w[56],0x748f82ee5defb2fc);
    _ROUND64(h,a,b,c,d,e,f,g,w[57],0x78a5636f43172f60);
    _ROUND64(g,h,a,b,c,d,e,f,w[58],0x84c87814a1f0ab72);
    _ROUND64(f,g,h,a,b,c,d,e,w[59],0x8cc702081a6439ec);
    _ROUND64(e,f,g,h,a,b,c,d,w[60],0x90befffa23631e28);
    _ROUND64(d,e,f,g,h,a,b,c,w[61],0xa4506cebde82bde9);
    _ROUND64(c,d,e,f,g,h,a,b,w[62],0xbef9a3f7b2c67915);
    _ROUND64(b,c,d,e,f,g,h,a,w[63],0xc67178f2e372532b);
    _ROUND64(a,b,c,d,e,f,g,h,w[64],0xca273eceea26619c);
    _ROUND64(h,a,b,c,d,e,f,g,w[65],0xd186b8c721c0c207);
    _ROUND64(g,h,a,b,c,d,e,f,w[66],0xeada7dd6cde0eb1e);
    _ROUND64(f,g,h,a,b,c,d,e,w[67],0xf57d4f7fee6ed178);
    _ROUND64(e,f,g,h,a,b,c,d,w[68],0x06f067aa72176fba);
    _ROUND64(d,e,f,g,h,a,b,c,w[69],0x0a637dc5a2c898a6);
    _ROUND64(c,d,e,f,g,h,a,b,w[70],0x113f9804bef90dae);
    _ROUND64(b,c,d,e,f,g,h,a,w[71],0x1b710b35131c471b);
    _ROUND64(a,b,c,d,e,f,g,h,w[72],0x28db77f523047d84);
    _ROUND64(h,a,b,c,d,e,f,g,w[73],0x32caab7b40c72493);
    _ROUND64(g,h,a,b,c,d,e,f,w[74],0x3c9ebe0a15c9bebc);
    _ROUND64(f,g,h,a,b,c,d,e,w[75],0x431d67c49c100d4c);
    _ROUND64(e,f,g,h,a,b,c,d,w[76],0x4cc5d4becb3e42b6);
    _ROUND64(d,e,f,g,h,a,b,c,w[77],0x597f299cfc657e2a);
    _ROUND64(c,d,e,f,g,h,a,b,w[78],0x5fcb6fab3ad6faec);
    _ROUND64(b,c,d,e,f,g,h,a,w[79],0x6c44198c4a475817);
    // add to cumulative hash
    hash[0] += a, hash[1] += b, hash[2] += c, hash[3] += d, hash[4] += e, hash[5] += f, hash[6] += g, hash[7] += h;
}

// block hashing for 224 and 256
void _hash256_helper(const uint8_t * restrict array, size_t len, uint8_t * restrict hash, const uint32_t * restrict init)
{
    const uint8_t *end = array + len;
    const uint8_t *block = array;
    uint32_t h[8];
    memcpy(h,init,32);
    while (block + 64 <= end)
    {
        hash_sha256_block(h,(uint32_t*)block);
        block += 64;
    }
    // padding
    uint8_t buf[128];
    size_t buf_len = 0;
    size_t block_len = end - block;
    _pad1(buf,&buf_len,block,block_len,bswap_64(len<<3)); // big endian length
    // hash last blocks
    hash_sha256_block(h,(uint32_t*)buf);
    if (buf_len == 128)
        hash_sha256_block(h,(uint32_t*)buf+16);
    h[0] = bswap_32(h[0]);
    h[1] = bswap_32(h[1]);
    h[2] = bswap_32(h[2]);
    h[3] = bswap_32(h[3]);
    h[4] = bswap_32(h[4]);
    h[5] = bswap_32(h[5]);
    h[6] = bswap_32(h[6]);
    h[7] = bswap_32(h[7]);
    memcpy(hash,h,32);
}

// block hashing for 384 and 512
void _hash512_helper(const uint8_t * restrict array, size_t len, uint8_t * restrict hash, const uint64_t * restrict init)
{
    const uint8_t *end = array + len;
    const uint8_t *block = array;
    uint64_t h[8];
    memcpy(h,init,64);
    while (block + 128 <= end)
    {
        hash_sha512_block(h,(uint64_t*)block);
        block += 128;
    }
    // padding
    uint8_t buf[256];
    size_t buf_len = 0;
    size_t block_len = end - block;
    _pad2(buf,&buf_len,block,block_len,bswap_64(len<<3));
    // hash last blocks
    hash_sha512_block(h,(uint64_t*)buf);
    if (buf_len == 256)
        hash_sha512_block(h,(uint64_t*)buf+16);
    h[0] = bswap_64(h[0]);
    h[1] = bswap_64(h[1]);
    h[2] = bswap_64(h[2]);
    h[3] = bswap_64(h[3]);
    h[4] = bswap_64(h[4]);
    h[5] = bswap_64(h[5]);
    h[6] = bswap_64(h[6]);
    h[7] = bswap_64(h[7]);
    memcpy(hash,h,64);
}

void hash_sha256_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash)
{
    uint32_t h[8];
    _hash256_helper(array,len,(uint8_t*)h,_SHA256_INIT);
    memcpy(hash,h,32);
}

void hash_sha224_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash)
{
    uint32_t h[8];
    _hash256_helper(array,len,(uint8_t*)h,_SHA224_INIT);
    memcpy(hash,h,28);
}

void hash_sha512_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash)
{
    uint64_t h[8];
    _hash512_helper(array,len,(uint8_t*)h,_SHA512_INIT);
    memcpy(hash,h,64);
}

void hash_sha384_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash)
{
    uint64_t h[8];
    _hash512_helper(array,len,(uint8_t*)h,_SHA384_INIT);
    memcpy(hash,h,48);
}
