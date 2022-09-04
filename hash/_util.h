#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// padding function for md4,md5,sha1
static inline void _pad1(uint8_t *buf, size_t *buf_len, const uint8_t *block, size_t block_len, size_t msg_len)
{
    memcpy(buf,block,block_len);
    *buf_len = block_len;
    buf[(*buf_len)++] = 0x80; // pad to length = 56 mod 64
    if (*buf_len <= 56) // pad to 56
    {
        memset(buf+*buf_len,0,56-*buf_len);
        *buf_len = 56;
    }
    else // pad to 64+56
    {
        memset(buf+*buf_len,0,64+56-*buf_len);
        *buf_len = 64+56;
    }
    memcpy(buf+*buf_len,&msg_len,8);
    *buf_len += 8;
}
