#include "hash.h"

#include <byteswap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_u32hbe(uint32_t *a, size_t l)
{
    while (l--)
        printf("%08x",bswap_32(*(a++)));
    printf("\n");
}

void print_u64hbe(uint64_t *a, size_t l)
{
    while (l--)
        printf("%08lx",bswap_64(*(a++)));
    printf("\n");
}

void test_md2()
{
    char *m[3] =
    {
        "The quick brown fox jumps over the lazy dog",
        "The quick brown fox jumps over the lazy cog",
        ""
    };
    uint32_t h[4];
    for (size_t i = 0; i < 3; ++i)
    {
        hash_md2_bytes((uint8_t*)m[i],strlen(m[i]),(uint8_t*)&h);
        print_u32hbe(h,4);
    }
}

void test_md4()
{
    char *m[9] =
    {
        "The quick brown fox jumps over the lazy dog",
        "The quick brown fox jumps over the lazy cog",
        "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    };
    uint8_t *c[2] =
    {
        (uint8_t*)"\x83\x9c\x7a\x4d\x7a\x92\xcb\x56\x78\xa5\xd5\xb9\xee\xa5\xa7\x57\x3c\x8a\x74\xde\xb3\x66\xc3\xdc\x20\xa0\x83\xb6\x9f\x5d\x2a\x3b\xb3\x71\x9d\xc6\x98\x91\xe9\xf9\x5e\x80\x9f\xd7\xe8\xb2\x3b\xa6\x31\x8e\xdd\x45\xe5\x1f\xe3\x97\x08\xbf\x94\x27\xe9\xc3\xe8\xb9",
        (uint8_t*)"\x83\x9c\x7a\x4d\x7a\x92\xcb\xd6\x78\xa5\xd5\x29\xee\xa5\xa7\x57\x3c\x8a\x74\xde\xb3\x66\xc3\xdc\x20\xa0\x83\xb6\x9f\x5d\x2a\x3b\xb3\x71\x9d\xc6\x98\x91\xe9\xf9\x5e\x80\x9f\xd7\xe8\xb2\x3b\xa6\x31\x8e\xdc\x45\xe5\x1f\xe3\x97\x08\xbf\x94\x27\xe9\xc3\xe8\xb9"
    };
    uint32_t h[4];
    for (size_t i = 0; i < 9; ++i)
    {
        hash_md4_bytes((uint8_t*)m[i],strlen(m[i]),(uint8_t*)&h);
        print_u32hbe(h,4);
    }
    for (size_t i = 0; i < 2; ++i)
    {
        hash_md4_bytes(c[i],64,(uint8_t*)&h);
        print_u32hbe(h,4);
    }
}

void test_md5()
{
    char *m[3] =
    {
        "The quick brown fox jumps over the lazy dog",
        "The quick brown fox jumps over the lazy dog.",
        ""
    };
    uint8_t *c[2] =
    {
        (uint8_t*)"\xd1\x31\xdd\x02\xc5\xe6\xee\xc4\x69\x3d\x9a\x06\x98\xaf\xf9\x5c\x2f\xca\xb5\x87\x12\x46\x7e\xab\x40\x04\x58\x3e\xb8\xfb\x7f\x89\x55\xad\x34\x06\x09\xf4\xb3\x02\x83\xe4\x88\x83\x25\x71\x41\x5a\x08\x51\x25\xe8\xf7\xcd\xc9\x9f\xd9\x1d\xbd\xf2\x80\x37\x3c\x5b\xd8\x82\x3e\x31\x56\x34\x8f\x5b\xae\x6d\xac\xd4\x36\xc9\x19\xc6\xdd\x53\xe2\xb4\x87\xda\x03\xfd\x02\x39\x63\x06\xd2\x48\xcd\xa0\xe9\x9f\x33\x42\x0f\x57\x7e\xe8\xce\x54\xb6\x70\x80\xa8\x0d\x1e\xc6\x98\x21\xbc\xb6\xa8\x83\x93\x96\xf9\x65\x2b\x6f\xf7\x2a\x70",
        (uint8_t*)"\xd1\x31\xdd\x02\xc5\xe6\xee\xc4\x69\x3d\x9a\x06\x98\xaf\xf9\x5c\x2f\xca\xb5\x07\x12\x46\x7e\xab\x40\x04\x58\x3e\xb8\xfb\x7f\x89\x55\xad\x34\x06\x09\xf4\xb3\x02\x83\xe4\x88\x83\x25\xf1\x41\x5a\x08\x51\x25\xe8\xf7\xcd\xc9\x9f\xd9\x1d\xbd\x72\x80\x37\x3c\x5b\xd8\x82\x3e\x31\x56\x34\x8f\x5b\xae\x6d\xac\xd4\x36\xc9\x19\xc6\xdd\x53\xe2\x34\x87\xda\x03\xfd\x02\x39\x63\x06\xd2\x48\xcd\xa0\xe9\x9f\x33\x42\x0f\x57\x7e\xe8\xce\x54\xb6\x70\x80\x28\x0d\x1e\xc6\x98\x21\xbc\xb6\xa8\x83\x93\x96\xf9\x65\xab\x6f\xf7\x2a\x70"
    };
    uint32_t h[4];
    for (size_t i = 0; i < 3; ++i)
    {
        hash_md5_bytes((uint8_t*)m[i],strlen(m[i]),(uint8_t*)&h);
        print_u32hbe(h,4);
    }
    for (size_t i = 0; i < 2; ++i)
    {
        hash_md5_bytes(c[i],128,(uint8_t*)&h);
        print_u32hbe(h,4);
    }
}

void test_sha1()
{
    char *m[3] =
    {
        "The quick brown fox jumps over the lazy dog",
        "The quick brown fox jumps over the lazy cog",
        ""
    };
    uint32_t h[5];
    for (size_t i = 0; i < 3; ++i)
    {
        hash_sha1_bytes((uint8_t*)m[i],strlen(m[i]),(uint8_t*)&h);
        print_u32hbe(h,5);
    }
}

void test_sha256()
{
    char *m[1] =
    {
        ""
    };
    uint32_t h[8];
    for (size_t i = 0; i < 1; ++i)
    {
        hash_sha256_bytes((uint8_t*)m[i],strlen(m[i]),(uint8_t*)&h);
        print_u32hbe(h,8);
    }
}

void test_sha224()
{
    char *m[3] =
    {
        "The quick brown fox jumps over the lazy dog",
        "The quick brown fox jumps over the lazy dog.",
        ""
    };
    uint32_t h[7];
    for (size_t i = 0; i < 3; ++i)
    {
        hash_sha224_bytes((uint8_t*)m[i],strlen(m[i]),(uint8_t*)&h);
        print_u32hbe(h,7);
    }
}

void test_sha512()
{
    char *m[1] =
    {
        ""
    };
    uint64_t h[8];
    for (size_t i = 0; i < 1; ++i)
    {
        hash_sha512_bytes((uint8_t*)m[i],strlen(m[i]),(uint8_t*)&h);
        print_u64hbe(h,8);
    }
}

void test_sha384()
{
    char *m[1] =
    {
        ""
    };
    uint64_t h[8];
    for (size_t i = 0; i < 1; ++i)
    {
        hash_sha384_bytes((uint8_t*)m[i],strlen(m[i]),(uint8_t*)&h);
        print_u64hbe(h,6);
    }
}

void test_ripemd128()
{
    char *m[8] =
    {
        "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    };
    uint32_t h[4];
    for (size_t i = 0; i < 8; ++i)
    {
        hash_ripemd128_bytes((uint8_t*)m[i],strlen(m[i]),(uint8_t*)&h);
        print_u32hbe(h,4);
    }
}

void test_ripemd160()
{
    char *m[10] =
    {
        "The quick brown fox jumps over the lazy dog",
        "The quick brown fox jumps over the lazy cog",
        "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    };
    uint32_t h[5];
    for (size_t i = 0; i < 10; ++i)
    {
        hash_ripemd160_bytes((uint8_t*)m[i],strlen(m[i]),(uint8_t*)&h);
        print_u32hbe(h,5);
    }
}

int main(int argc, char **argv)
{
    printf("md2\n");
    test_md2();
    printf("md4\n");
    test_md4();
    printf("md5\n");
    test_md5();
    printf("sha1\n");
    test_sha1();
    printf("sha256\n");
    test_sha256();
    printf("sha224\n");
    test_sha224();
    printf("sha512\n");
    test_sha512();
    printf("sha384\n");
    test_sha384();
    printf("ripemd128\n");
    test_ripemd128();
    printf("ripemd160\n");
    test_ripemd160();
    return 0;
}
