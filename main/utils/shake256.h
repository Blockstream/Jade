#ifndef SHAKE256_H_
#define SHAKE256_H_

#include <stddef.h>
#include <stdint.h>

struct shake256_ctx {
    uint64_t state[25];
    unsigned int pos;
};

void shake256_init(struct shake256_ctx* ctx, const uint8_t* init_data, size_t data_size);
void shake256_fill_data(struct shake256_ctx* ctx, uint8_t* output, size_t output_size);
int shake256_mbedtls_rnd_cb(void* ctx, uint8_t* buf, size_t len);

#endif
