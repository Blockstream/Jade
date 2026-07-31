#ifndef AMALGAMATED_BUILD
#include "bip39.h"
#include "jade_wally_verify.h"

#include <wally_bip39.h>

size_t jade_bip39_entropy_len_from_word_count(const size_t nwords)
{
    switch (nwords) {
    case 12:
        return BIP39_ENTROPY_LEN_128;
    case 15:
        return BIP39_ENTROPY_LEN_160;
    case 18:
        return BIP39_ENTROPY_LEN_192;
    case 21:
        return BIP39_ENTROPY_LEN_224;
    case 24:
        return BIP39_ENTROPY_LEN_256;
    default:
        return 0;
    }
}

size_t jade_bip39_word_count_from_entropy_len(const size_t entropy_len)
{
    switch (entropy_len) {
    case BIP39_ENTROPY_LEN_128:
        return 12;
    case BIP39_ENTROPY_LEN_160:
        return 15;
    case BIP39_ENTROPY_LEN_192:
        return 18;
    case BIP39_ENTROPY_LEN_224:
        return 21;
    case BIP39_ENTROPY_LEN_256:
        return 24;
    default:
        return 0;
    }
}

bool jade_bip39_word_count_valid(const size_t nwords) { return jade_bip39_entropy_len_from_word_count(nwords) != 0; }

bool jade_bip39_mnemonic_validate(const char* mnemonic)
{
    if (!mnemonic) {
        return false;
    }

    uint8_t entropy[BIP39_ENTROPY_LEN_256];
    size_t entropy_len = 0;
    const int wret = bip39_mnemonic_to_bytes(NULL, mnemonic, entropy, sizeof(entropy), &entropy_len);
    JADE_WALLY_VERIFY(wally_bzero(entropy, sizeof(entropy)));
    return wret == WALLY_OK && jade_bip39_word_count_from_entropy_len(entropy_len) != 0;
}
#endif // AMALGAMATED_BUILD
