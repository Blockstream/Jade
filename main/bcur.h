#ifndef BCUR_H_
#define BCUR_H_

#include <stdbool.h>
#include <stddef.h>

// Parse BC-UR messages - decodes BC-UR and parses nested CBOR
bool bcur_parse_bip39(const char* bcur, size_t bcur_len, char* mnemonic, size_t mnemonic_len, size_t* written);

#endif /* BCUR_H_ */
