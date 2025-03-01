#include "psbt.h"
#include "../keychain.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"

#include <wally_map.h>
#include <wally_psbt.h>

static bool key_iter_init(const struct wally_psbt* psbt, const size_t index, const bool is_input, key_iter* iter)
{
    JADE_ASSERT(psbt);
    JADE_ASSERT(index <= (is_input ? psbt->num_inputs : psbt->num_outputs));
    JADE_ASSERT(iter);
    iter->psbt = psbt;
    iter->index = index;
    iter->key_index = 0;
    --iter->key_index; // Incrementing will wrap around to 0 i.e. the first key
    iter->is_input = is_input;
    iter->is_taproot = false; // FIXME: Add support for taproot
    iter->is_valid = true;
    return key_iter_next(iter);
}

bool key_iter_input_begin(const struct wally_psbt* psbt, const size_t index, key_iter* iter)
{
    return key_iter_init(psbt, index, true, iter);
}

bool key_iter_output_begin(const struct wally_psbt* psbt, const size_t index, key_iter* iter)
{
    return key_iter_init(psbt, index, false, iter);
}

static const struct wally_map* key_iter_get_keypaths(const key_iter* iter)
{
    JADE_ASSERT(iter && iter->is_valid);
    if (iter->is_input) {
        return &iter->psbt->inputs[iter->index].keypaths;
    }
    return &iter->psbt->outputs[iter->index].keypaths;
}

bool key_iter_next(key_iter* iter)
{
    const struct wally_map* keypaths = key_iter_get_keypaths(iter);
    size_t key_index;
    ++iter->key_index;
    JADE_WALLY_VERIFY(wally_map_keypath_get_bip32_key_from(
        keypaths, iter->key_index, &keychain_get()->xpriv, &iter->hdkey, &key_index));
    if (key_index) {
        iter->is_valid = true; // Found
        iter->key_index = key_index - 1; // Adjust to 0-based index
    } else {
        iter->is_valid = false; // Not found
    }
    return iter->is_valid;
}

size_t key_iter_get_num_keys(const key_iter* iter)
{
    const struct wally_map* keypaths = key_iter_get_keypaths(iter);
    return keypaths->num_items;
}

bool key_iter_contains_pubkey(const key_iter* iter, const uint8_t* pubkey, const size_t pubkey_len)
{
    const struct wally_map* keypaths = key_iter_get_keypaths(iter);
    size_t written;
    const int ret = wally_map_find(keypaths, pubkey, pubkey_len, &written);
    return ret == WALLY_OK && written != 0;
}

bool key_iter_get_pubkey_at(const key_iter* iter, const size_t key_index, uint8_t* pubkey, const size_t pubkey_len)
{
    const struct wally_map* keypaths = key_iter_get_keypaths(iter);
    size_t written;
    const int ret = wally_map_get_item_key(keypaths, key_index, pubkey, pubkey_len, &written);
    // written must exactly match pubkey_len, so that we only match
    // compressed/uncompressed pubkeys depending on the callers intent
    return ret == WALLY_OK && written == pubkey_len;
}

void key_iter_get_fingerprint_at(
    const key_iter* iter, const size_t key_index, uint8_t* fingerprint, const size_t fingerprint_len)
{
    const struct wally_map* keypaths = key_iter_get_keypaths(iter);
    const int ret = wally_map_keypath_get_item_fingerprint(keypaths, key_index, fingerprint, fingerprint_len);
    JADE_WALLY_VERIFY(ret);
}

bool key_iter_get_path_at(
    const key_iter* iter, const size_t key_index, uint32_t* path, const size_t path_len, size_t* written)
{
    const struct wally_map* keypaths = key_iter_get_keypaths(iter);
    const int ret = wally_map_keypath_get_item_path(keypaths, key_index, path, path_len, written);
    return ret == WALLY_OK && *written <= path_len;
}

bool key_iter_get_path(const key_iter* iter, uint32_t* path, const size_t path_len, size_t* written)
{
    return key_iter_get_path_at(iter, iter->key_index, path, path_len, written);
}
