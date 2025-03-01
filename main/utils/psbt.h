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

// Get the number of keys in the keypaths the iterator current points to
size_t key_iter_get_num_keys(const key_iter* iter);

// Returns true if the keypaths the iterator current points to contain `pubkey`
bool key_iter_contains_pubkey(const key_iter* iter, const uint8_t* pubkey, size_t pubkey_len);

// Get the public key of the `key_index`th key in the keypath the iterator current points to
bool key_iter_get_pubkey_at(const key_iter* iter, size_t key_index, uint8_t* pubkey, size_t pubkey_len);

// Get the fingerprint of the `key_index`th key in the keypath the iterator current points to
void key_iter_get_fingerprint_at(const key_iter* iter, size_t key_index, uint8_t* fingerprint, size_t fingerprint_len);

// Get the path to the `key_index`th key in the keypath the iterator current points to
bool key_iter_get_path_at(const key_iter* iter, size_t key_index, uint32_t* path, size_t path_len, size_t* written);

#endif /* PSBT_H_ */
