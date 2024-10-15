#include "utils/shake256.h"
#include <stdint.h>
#include <string.h>

// Keccak round constants
static const uint64_t keccakf_rndc[24] = { 0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL, 0x000000008000808bULL,
    0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL,
    0x8000000080008008ULL };

// Keccak rotation offsets
static const int keccakf_rotc[24]
    = { 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44 };

// Keccak permutation indices
static const int keccakf_piln[24]
    = { 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1 };

// Keccak round function
static void keccakf(uint64_t st[25])
{
    int i, j, round;
    uint64_t t, bc[5];

    for (round = 0; round < 24; ++round) {
        // Theta
        for (i = 0; i < 5; ++i) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }

        for (i = 0; i < 5; ++i) {
            t = bc[(i + 4) % 5] ^ ((bc[(i + 1) % 5] << 1) | (bc[(i + 1) % 5] >> 63));
            for (j = 0; j < 25; j += 5) {
                st[j + i] ^= t;
            }
        }

        // Rho Pi
        t = st[1];
        for (i = 0; i < 24; ++i) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ((t << keccakf_rotc[i]) | (t >> (64 - keccakf_rotc[i])));
            t = bc[0];
        }

        // Chi
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; ++i) {
                bc[i] = st[j + i];
            }
            for (i = 0; i < 5; ++i) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        // Iota
        st[0] ^= keccakf_rndc[round];
    }
}

void shake256_init(struct shake256_ctx* ctx, const uint8_t* init_data, size_t data_size)
{
    memset(ctx, 0, sizeof(struct shake256_ctx));

    if (data_size > 136) {
        data_size = 136;
    }

    for (size_t i = 0; i < data_size; ++i) {
        ((uint8_t*)ctx->state)[i] ^= init_data[i];
    }

    // XOR the last byte with 0x1F (domain separator for SHAKE256)
    ((uint8_t*)ctx->state)[data_size] ^= 0x1F;

    // XOR the last byte of the state with 0x80
    ((uint8_t*)ctx->state)[135] ^= 0x80;

    keccakf(ctx->state);
}

void shake256_fill_data(struct shake256_ctx* ctx, uint8_t* output, const size_t output_size)
{
    size_t i;
    for (i = 0; i < output_size; ++i) {
        if (ctx->pos == 136) {
            keccakf(ctx->state);
            ctx->pos = 0;
        }
        output[i] = ((uint8_t*)ctx->state)[ctx->pos];
        ++ctx->pos;
    }
}

int shake256_mbedtls_rnd_cb(void* ctx, uint8_t* buf, const size_t len)
{
    struct shake256_ctx* sctx = (struct shake256_ctx*)ctx;
    shake256_fill_data(sctx, buf, len);
    return 0;
}
