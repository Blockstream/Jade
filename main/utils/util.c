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
#endif // AMALGAMATED_BUILD
