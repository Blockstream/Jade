#ifndef PSBT_H_
#define PSBT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wally_bip32.h>

struct wally_psbt;

/* An iterator for keypaths in a PSBT input or output.
 * The iterator holds the privately-derived key that corresponds to the
 * public keys it iterates, so use of this struct must be wrapped with
 * SENSITIVE_PUSH/SENSITIVE_POP.
 */
typedef struct key_iter_t {
    struct ext_key hdkey;
    const struct wally_psbt* psbt;
    size_t index;
    size_t key_index;
    bool is_input;
    bool is_taproot;
    bool is_valid;
} key_iter;

// Initialize a key iterator for the `index`th PSBT input
bool key_iter_input_begin(const struct wally_psbt* psbt, size_t index, key_iter* iter);

// Initialize a key iterator for the `index`th PSBT output
bool key_iter_output_begin(const struct wally_psbt* psbt, size_t index, key_iter* iter);

/* Advance a key iterator.
 * `is_valid` is set to true if a key was found, false otherwise.
 * When `is_valid` is true:
 *   - `hdkey` holds the privately derived key matching the found pubkey.
 *   - `key_index` holds the index of the key in the relevant keypath.
 */
bool key_iter_next(key_iter* iter);

// Get the path to the key the iterator current points to
bool key_iter_get_path(const key_iter* iter, uint32_t* path, size_t path_len, size_t* written);

#endif /* PSBT_H_ */
