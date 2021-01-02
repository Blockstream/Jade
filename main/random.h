#ifndef RANDOM_H_
#define RANDOM_H_

#include <stddef.h>

void refeed_entropy(const unsigned char* additional, size_t len);
void get_random(unsigned char* bytes_out, size_t len);
unsigned char get_uniform_random_byte(unsigned char upper_bound);

// this function needs to be called first thing when starting up
void random_start_collecting();

// this function needs to be called before any randomness is requested
void random_full_initialization();

#endif /* RANDOM_H_ */
