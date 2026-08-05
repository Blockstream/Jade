#ifndef JADE_BIP39_H_
#define JADE_BIP39_H_

#include <stdbool.h>
#include <stddef.h>

// Jade supports the standard BIP39 English mnemonic lengths.
#define MNEMONIC_MAXWORDS 24

// The longest valid words in the English wordlist are 8 characters.
#define MNEMONIC_MAX_WORD_LEN 8

// 24 8-character words + 23 spaces + NUL = 216 bytes.
#define MNEMONIC_BUFLEN 216

size_t jade_bip39_entropy_len_from_word_count(size_t nwords);
size_t jade_bip39_word_count_from_entropy_len(size_t entropy_len);
bool jade_bip39_word_count_valid(size_t nwords);
bool jade_bip39_mnemonic_validate(const char* mnemonic);

#endif /* JADE_BIP39_H_ */
