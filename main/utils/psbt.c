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

bool key_iter_next(key_iter* iter)
{
    JADE_ASSERT(iter && iter->is_valid);
    const struct wally_map* keypaths;
    size_t key_index;
    if (iter->is_input) {
        keypaths = &iter->psbt->inputs[iter->index].keypaths;
    } else {
        keypaths = &iter->psbt->outputs[iter->index].keypaths;
    }
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
