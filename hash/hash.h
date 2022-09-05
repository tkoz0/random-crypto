#pragma once

#include <stdint.h>
#include <stdlib.h>

void hash_md2_block(uint8_t * restrict C, uint8_t * restrict L, uint8_t * restrict X, const uint8_t * restrict block);
void hash_md2_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash);

void hash_md4_block(uint32_t * restrict hash, const uint32_t * restrict M);
void hash_md4_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash);

void hash_md5_block(uint32_t * restrict hash, const uint32_t * restrict M);
void hash_md5_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash);

void hash_sha1_block(uint32_t * restrict hash, const uint32_t * restrict M);
void hash_sha1_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash);

void hash_sha256_block(uint32_t * restrict hash, const uint32_t * restrict M);
void hash_sha512_block(uint64_t * restrict hash, const uint64_t * restrict M);
void hash_sha256_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash);
void hash_sha224_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash);
void hash_sha512_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash);
void hash_sha384_bytes(const uint8_t * restrict array, size_t len, uint8_t * restrict hash);
