#ifndef RANDOM_H_
#define RANDOM_H_

#include <stddef.h>
#include <stdint.h>

void refeed_entropy(const uint8_t* additional, size_t len);
void get_random(uint8_t* bytes_out, size_t len);
uint8_t get_uniform_random_byte(uint8_t upper_bound);

// this function needs to be called first thing when starting up
void random_start_collecting(void);

// this function needs to be called before any randomness is requested
void random_full_initialization(void);

#endif /* RANDOM_H_ */
