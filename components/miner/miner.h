#ifndef MINER_H_
#define MINER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* We need a way to tell the miner to us that there is a solution */
typedef void (*solution_cb)(void* ctx, const uint8_t*, uint32_t);

/* We need a way to start the machinery */
void start_miners(void** ctx, solution_cb cb, void* cbctx);

/* A way to stop it */
void stop_miners(void* ctx);

/* A way to tell it about new template */
uint64_t on_new_target(void* ctx, uint32_t version, const uint8_t* previousblockhash, const uint8_t* target,
    uint32_t curtime, uint32_t bits, uint32_t height, const char* address);

/* this tringgers the solution_cb callback */
bool check_solutions(void* ctx);

/* returns the total number of hashes per second */
void check_speed(void* ctx, uint32_t* speed);

#endif /* MINER_H_ */
