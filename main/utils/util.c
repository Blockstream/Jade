#ifndef AMALGAMATED_BUILD
#include "util.h"
#include "../wallet.h"

// Green user path:
// Main account:
//     m/1/pointer
// Subaccounts:
//     m/3'/subaccount'/1/pointer
bool is_potential_green_user_path(const uint32_t* path, const size_t path_len, uint32_t* subaccount_out)
{
    if (path_len != GA_USER_PATH_MAX_LEN) {
        // Main account path looks just like a recovery path, so check that
        if (is_potential_green_recovery_path(path, path_len)) {
            *subaccount_out = 0; // Main account
            return true;
        }
        return false;
    }
    if (path[0] == harden(3) && ishardened(path[1]) && path[2] == 1 && path[3] && !ishardened(path[3])) {
        *subaccount_out = unharden(path[1]); // Subaccount
        return true;
    }
    return false;
}

// Green (user) recovery path:
// Subaccounts:
//     m/1/pointer
// NOTE: The main account (subaccount 0) cannot be a recovery path,
//       so there is no main account path formulation.
bool is_potential_green_recovery_path(const uint32_t* path, const size_t path_len)
{
    if (path_len != GA_RECOVERY_PATH_LEN) {
        return false;
    }
    return path[0] == 1 && !ishardened(path[1]);
}

// Green server path
// Main account
//     m/1/gait_path/pointer
// Subaccounts:
//     m/3/gait_path/subaccount/pointer
bool is_potential_green_server_path(const uint32_t* path, const size_t path_len, uint32_t* subaccount_out)
{
    if (path_len == MAX_GASERVICE_PATH_LEN - 1) {
        if (path[0] != 1) {
            return false; // Main account indicator not present
        }
    } else if (path_len == MAX_GASERVICE_PATH_LEN) {
        if (path[0] != 3) {
            return false; // Subaccount indicator not present
        }
    } else {
        return false;
    }
    const size_t tail_len = path_len == MAX_GASERVICE_PATH_LEN ? 2 : 1;
    for (size_t i = 1; i < path_len; ++i) {
        if (i < path_len - tail_len && path[i] > 0xffff) {
            return false; // Not a Green server path element
        } else if (ishardened(path[i])) {
            return false; // Hardened subaccount or pointer not allowed
        }
    }
    *subaccount_out = path_len == MAX_GASERVICE_PATH_LEN ? path[path_len - 2] : 0;
    return true;
}

void split_text(const char* src, const size_t len, const size_t wordlen, char* output, const size_t output_len,
    size_t* num_words, size_t* written)
{
    JADE_ASSERT(src);
    JADE_ASSERT(wordlen);
    JADE_ASSERT(output);
    JADE_ASSERT(output_len >= SPLIT_TEXT_LEN(len, wordlen));
    JADE_INIT_OUT_SIZE(num_words);
    JADE_INIT_OUT_SIZE(written);

    size_t read = 0;
    size_t write = 0;
    while (read < len) {
        const size_t remaining = len - read;
        const size_t nchars = remaining > wordlen ? wordlen : remaining;

        JADE_ASSERT(write + nchars + 1 <= output_len);
        strncpy(output + write, src + read, nchars);
        read += nchars;
        write += nchars;

        output[write++] = '\0';
        ++*num_words;
    }
    JADE_ASSERT(write <= output_len);
    *written = write;
}

size_t base32_to_bin(const char* b32_str, const size_t b32_str_len, uint8_t* bin, const size_t bin_len)
{
    JADE_ASSERT(b32_str && b32_str_len);
    JADE_ASSERT(bin && bin_len);

    size_t written = 0;
    unsigned int tmp = 0;
    uint8_t num_bits = 0;
    const char* b32_str_end = b32_str + b32_str_len;
    while (b32_str < b32_str_end && *b32_str) {
        char ch = *b32_str++;

        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
            ch = (ch & 0x1F) - 1;
        } else if (ch >= '2' && ch <= '7') {
            ch -= 24;
        } else if (ch == '=') {
            break; // Padding char - end of meaningful input
        } else {
            return 0; // Bad character
        }

        tmp <<= 5;
        tmp |= ch;
        num_bits += 5; // Read 5 bits
        if (num_bits >= 8) {
            // Write 8 bits
            if (written >= bin_len) {
                return 0; // Destination size insufficient
            }
            num_bits -= 8;
            bin[written++] = tmp >> num_bits;
        }
    }
    return written;
}

static const char b32_alphabet[32] = {
    // Base 32 encoding characters from rfc4648
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7'
};

bool bin_to_base32(const uint8_t* bin, const size_t bin_len, char* b32_str, const size_t b32_str_len, bool use_padding)
{
    JADE_ASSERT(bin && bin_len);
    JADE_ASSERT(b32_str && b32_str_len);

    const size_t required_chars = (bin_len * 8 + 4) / 5;
    size_t required_padding = use_padding && required_chars % 8 ? 8 - required_chars % 8 : 0;

    if (b32_str_len < required_chars + required_padding + 1) {
        JADE_LOGE("Buffer too small in bin_to_base32");
        return false; // Destination size insufficient
    }

    unsigned int tmp = 0;
    uint8_t num_bits = 0;
    const uint8_t* bin_end = bin + bin_len;
    char* out = b32_str;
    while (bin < bin_end) {
        tmp <<= 8;
        tmp |= *bin++;
        num_bits += 8;
        while (num_bits >= 5) {
            *out++ = b32_alphabet[(tmp >> (num_bits - 5)) & 0x1F];
            num_bits -= 5;
        }
    }
    if (num_bits > 0) {
        *out++ = b32_alphabet[(tmp << (5 - num_bits)) & 0x1F];
    }
    // Append '=' padding to a multiple of 8 if requested
    while (required_padding) {
        *out++ = '=';
        --required_padding;
    }
    *out = '\0';
    return true;
}
#endif // AMALGAMATED_BUILD
