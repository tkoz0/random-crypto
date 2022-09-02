#include <assert.h>
#include <byteswap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "jrand.h"

int main(int argc, char **argv)
{
    if (argc < 5 || argc > 6)
    {
        fprintf(stderr,"usage: ./a.out <file> <calls> <seed> <function> [param]\n");
        return 0;
    }
    char *fname = argv[1];
    int32_t calls = atoi(argv[2]);
    int64_t seed = atoll(argv[3]);
    char *func = argv[4];
    char *param = NULL;
    if (argc == 6)
        param = argv[5];
    FILE *outf = fopen(fname,"wb");
    assert(outf);
    jrand_t jrand;
    jrand_init_seed(&jrand,seed);
    if (!strcmp(func,"nextBytes"))
    {
        assert(param);
        int32_t num_bytes = atoi(param);
        int8_t *byte_arr = malloc(num_bytes);
        while (calls--)
        {
            jrand_next_bytes(&jrand,byte_arr,num_bytes);
            fwrite(byte_arr,1,num_bytes,outf);
        }
        free(byte_arr);
    }
    else if (!strcmp(func,"nextInt"))
    {
        if (param)
        {
            int32_t mod = atoi(param);
            while (calls--)
            {
                int32_t num = bswap_32(jrand_next_int_mod(&jrand,mod));
                fwrite(&num,4,1,outf);
            }
        }
        else
        {
            while (calls--)
            {
                int32_t num = bswap_32(jrand_next_int(&jrand));
                fwrite(&num,4,1,outf);
            }
        }
    }
    else if (!strcmp(func,"nextLong"))
    {
        while (calls--)
        {
            int64_t num = bswap_64(jrand_next_long(&jrand));
            fwrite(&num,8,1,outf);
        }
    }
    else if (!strcmp(func,"nextBoolean"))
    {
        while (calls--)
        {
            bool num = jrand_next_bool(&jrand);
            fwrite(&num,1,1,outf);
        }
    }
    else if (!strcmp(func,"nextFloat"))
    {
        while (calls--)
        {
            union { float numf; int32_t numi; } u;
            u.numf = jrand_next_float(&jrand);
            u.numi = bswap_32(u.numi);
            fwrite(&u.numi,4,1,outf);
        }
    }
    else if (!strcmp(func,"nextDouble"))
    {
        while (calls--)
        {
            union { double numd; int64_t numi; } u;
            u.numd = jrand_next_double(&jrand);
            u.numi = bswap_64(u.numi);
            fwrite(&u.numi,8,1,outf);
        }
    }
    else if (!strcmp(func,"nextGaussian"))
    {
        while (calls--)
        {
            union { double numd; int64_t numi; } u;
            u.numd = jrand_next_gaussian(&jrand);
            u.numi = bswap_64(u.numi);
            fwrite(&u.numi,8,1,outf);
        }
    }
    else
    {
        fprintf(stderr,"invalid function name \"%s\"\n",func);
        return 1;
    }
    fclose(outf);
    return 0;
}
