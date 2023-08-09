#include "descriptor.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "utils/malloc_ext.h"
#include "utils/network.h"
#include "utils/temporary_stack.h"
#include "wallet.h"

#include <wally_address.h>
#include <wally_descriptor.h>
#include <wally_script.h>

struct ext_key;
#include <wally_map.h>

#include <sodium/utils.h>

// Stack size required for miniscript parsing.
// Allow 1k, plus 1k per 'depth' level, plus 4k for handling the
// public keys which are expected to be at the end of most branches.
#define DESCRIPTOR_PARSE_STACK_SIZE(depth) ((depth + 5) * 1024)

// We reject generating addresses from descriptors more than a certain depth, as this process
// is recursive and so can use unbounded amounts of stack.  This protects us against a badly-
// formed (or deliberately malicious) script causing a stack overflow.
// Parsing is similar but far less stack intensive - so we allow parsing a greater depth so we
// can successfully parse deep scripts and then reject with a meaningful 'too deep' error.
static const uint8_t MAX_DESCRIPTOR_ALLOWED_DEPTH = 12; // corresponds to a 17k stack
static const uint8_t MAX_DESCRIPTOR_PARSING_DEPTH = 25; // just for sanity

// Workaround to run 'wally_descriptor_to_address()' on a temporary stack, as it can
// require between 8 and 16kb of stack space for reasonable miniscript descriptors.
typedef struct {
    const struct wally_descriptor* descriptor;
    const uint32_t multi_index;
    const uint32_t child_num;
    uint8_t* script_output;
    size_t script_len;
    char* addr_output;
} descriptor_evaluation_data_t;

static bool descriptor_to_address_impl(void* ctx)
{
    JADE_ASSERT(ctx);
    descriptor_evaluation_data_t* const data = (descriptor_evaluation_data_t*)ctx;
    JADE_ASSERT(!data->addr_output);

    const uint32_t variant = 0;
    const uint32_t flags = 0;

    return wally_descriptor_to_address(
               data->descriptor, variant, data->multi_index, data->child_num, flags, &data->addr_output)
        == WALLY_OK;
}

static bool descriptor_to_script_impl(void* ctx)
{
    JADE_ASSERT(ctx);
    descriptor_evaluation_data_t* const data = (descriptor_evaluation_data_t*)ctx;
    JADE_ASSERT(!data->script_output);

    const uint32_t variant = 0;
    const uint32_t flags = 0;
    const uint32_t depth = 0;
    const uint32_t index = 0;

    size_t maxlen = 0;
    if (wally_descriptor_to_script_get_maximum_length(
            data->descriptor, depth, index, variant, data->multi_index, data->child_num, flags, &maxlen)
            != WALLY_OK
        || !maxlen) {
        JADE_LOGE("Failed to get descriptor script length");
        return false;
    }

    uint8_t* script = JADE_MALLOC(maxlen);
    size_t written = 0;
    if (wally_descriptor_to_script(data->descriptor, depth, index, variant, data->multi_index, data->child_num, flags,
            script, maxlen, &written)
            != WALLY_OK
        || !written || written > maxlen) {
        JADE_LOGE("Failed to get descriptor script");
        free(script);
        return false;
    }

    // Ok, script generated
    data->script_output = script;
    data->script_len = written;
    return true;
}

// Map must have been initialised with 'wally_map_init()' already.
// (Ideally with size of [at least] num_values)
static void string_values_to_map(const string_value_t* datavalues, const size_t num_values, struct wally_map* output)
{
    JADE_ASSERT(datavalues || !num_values);
    JADE_ASSERT(output);

    // Copy each key/value into the map struct
    for (size_t i = 0; i < num_values; ++i) {
        const string_value_t* const map_entry = datavalues + i;
        JADE_WALLY_VERIFY(wally_map_add(output, (const uint8_t*)map_entry->key, map_entry->key_len,
            (const uint8_t*)map_entry->value, map_entry->value_len));
    }
}

static bool parse_descriptor(const char* name, const descriptor_data_t* descriptor, const char* network,
    descriptor_type_t* deduced_type, struct wally_descriptor** output, uint32_t* depth, const char** errmsg)
{
    JADE_ASSERT(name);
    JADE_ASSERT(descriptor);
    JADE_ASSERT(!network || isValidNetwork(network));
    JADE_ASSERT(!deduced_type || *deduced_type == DESCRIPTOR_TYPE_UNKNOWN);
    JADE_INIT_OUT_PPTR(output);
    JADE_INIT_OUT_SIZE(depth);
    JADE_INIT_OUT_PPTR(errmsg);

    // If descriptor type is unknown, try mixed and miniscript-only types,
    // and return the type to the caller if requested.
    const bool type_unknown = (descriptor->type == DESCRIPTOR_TYPE_UNKNOWN);
    const descriptor_type_t trial_types[] = { DESCRIPTOR_TYPE_MIXED, DESCRIPTOR_TYPE_MINISCRIPT_ONLY };
    const descriptor_type_t passed_type[] = { descriptor->type };
    const descriptor_type_t* const types = type_unknown ? trial_types : passed_type;
    const uint8_t num_types = type_unknown ? 2 : 1;

    struct wally_descriptor* d = NULL;
    const uint32_t network_id = network ? networkToId(network) : WALLY_NETWORK_NONE;

    // Load any passed values into a wally_map
    struct wally_map values;
    JADE_WALLY_VERIFY(wally_map_init(descriptor->num_values, NULL, &values));
    string_values_to_map(descriptor->values, descriptor->num_values, &values);
    const uint32_t wallet_policy_flags
        = descriptor->num_values ? (WALLY_MINISCRIPT_POLICY_TEMPLATE | WALLY_MINISCRIPT_UNIQUE_KEYPATHS) : 0;

    // Parse descriptor string - note we pass a sanity max depth to protect against
    // stack overflow during parsing.  It's possible that parsing here succeeds but we later
    // reject the descriptor as 'too deep', as generating addresses is more stack intensive.
    // This allows for a more meaningful 'too deep' error, rather than a generic 'failed to parse'.
    const uint32_t max_depth_flags = MAX_DESCRIPTOR_PARSING_DEPTH << WALLY_MINISCRIPT_DEPTH_SHIFT;

    for (uint8_t i = 0; i < num_types; ++i) {
        const uint32_t miniscript_flags = (types[i] == DESCRIPTOR_TYPE_MINISCRIPT_ONLY) ? WALLY_MINISCRIPT_ONLY : 0;
        const uint32_t flags = wallet_policy_flags | miniscript_flags | max_depth_flags;
        const int ret = wally_descriptor_parse(descriptor->script, &values, network_id, flags, &d);
        JADE_ASSERT((ret != WALLY_OK) == !d);
        if (ret == WALLY_OK) {
            if (type_unknown) {
                JADE_LOGI("Descriptor '%s' parsed as type %u", name, types[i]);
            }
            if (deduced_type) {
                *deduced_type = types[i]; // return type for caller
            }
            break;
        }
    }
    JADE_WALLY_VERIFY(wally_map_clear(&values));

    if (!d) {
        JADE_LOGE("Descriptor '%s' failed to parse", name);
        *errmsg = "Failed to parse descriptor";
        return false;
    }

    // Check max stack depth and limit / reject if excessively deep
    JADE_WALLY_VERIFY(wally_descriptor_get_depth(d, depth));
    JADE_LOGI("Descriptor %s depth: %lu", name, *depth);
    if (*depth > MAX_DESCRIPTOR_ALLOWED_DEPTH) {
        JADE_LOGE("Descriptor '%s' too deep to allow execution and address generation.  Depth %lu, max allowed %u",
            name, *depth, MAX_DESCRIPTOR_ALLOWED_DEPTH);
        *errmsg = "Descriptor/script too deep";
        goto fail;
    }

    // Do not currently support multiple variants
    uint32_t num_variants = 0;
    JADE_WALLY_VERIFY(wally_descriptor_get_num_variants(d, &num_variants));
    if (num_variants != 1) {
        JADE_LOGE("Descriptor '%s' appears to have unsupported number of variants: %lu", name, num_variants);
        *errmsg = "Descriptors with multiple variants not supported";
        goto fail;
    }

    // Do not currently support private keys in descriptors
    uint32_t features = 0;
    JADE_WALLY_VERIFY(wally_descriptor_get_features(d, &features));
    if (features & WALLY_MS_IS_PRIVATE) {
        JADE_LOGE("Descriptor '%s' appears to contain private keys", name);
        *errmsg = "Descriptors with private keys are not supported";
        goto fail;
    }
    if (features & WALLY_MS_IS_X_ONLY) {
        JADE_LOGE("Descriptor '%s' appears to contain x-only keys (taproot?)", name);
        *errmsg = "Descriptors with x-only keys are not supported";
        goto fail;
    }
    if (!(features & WALLY_MS_IS_RANGED)) {
        JADE_LOGE("Descriptor '%s' appears not to contain any wildcards", name);
        *errmsg = "Descriptors without any wildcards are not supported";
        goto fail;
    }

    uint32_t num_paths = 0;
    JADE_WALLY_VERIFY(wally_descriptor_get_num_paths(d, &num_paths));
    if (num_paths > 2) {
        JADE_LOGE("Descriptor '%s' appears to contain unsupported paths", name);
        *errmsg = "Descriptors with more than two paths are not supported";
        goto fail;
    }

    // Return the descriptor
    *output = d;
    return true;

fail:
    JADE_WALLY_VERIFY(wally_descriptor_free(d));
    return false;
}

// NOTE: signers should either be sufficient to hold details for all signers, or NULL if
// the only value of interest is the number of signers in the descriptor.
bool descriptor_get_signers(const char* name, const descriptor_data_t* descriptor, const char* network,
    descriptor_type_t* deduced_type, signer_t* signers, const size_t signers_len, size_t* written, const char** errmsg)
{
    JADE_ASSERT(name);
    JADE_ASSERT(descriptor);
    JADE_ASSERT(!network || isValidNetwork(network));
    JADE_ASSERT(!deduced_type || *deduced_type == DESCRIPTOR_TYPE_UNKNOWN);
    JADE_ASSERT(!signers == !signers_len); // both or neither
    JADE_INIT_OUT_SIZE(written);
    JADE_INIT_OUT_PPTR(errmsg);

    bool retval = false;
    struct wally_descriptor* d = NULL;
    uint32_t depth = 0;
    if (!parse_descriptor(name, descriptor, network, deduced_type, &d, &depth, errmsg)) {
        JADE_ASSERT(!d);
        return false;
    }

    uint32_t num_keys = 0;
    if (wally_descriptor_get_num_keys(d, &num_keys) != WALLY_OK || !num_keys) {
        *errmsg = "Failed to get signer pubkeys from descriptor";
        goto cleanup;
    }

    if (!signers) {
        // Caller only wants number of signers
        *written = num_keys;
        retval = true;
        goto cleanup;
    }

    // If caller wants signer details, must pass sufficient output
    if (signers_len < num_keys) {
        *errmsg = "Insufficient output to fetch signer details from descriptor";
        goto cleanup;
    }

    for (size_t i = 0; i < num_keys; ++i) {
        signer_t* const signer = signers + i;

        // Check features supported
        char* str = NULL;
        uint32_t key_features = 0;
        if (wally_descriptor_get_key_features(d, i, &key_features) != WALLY_OK) {
            *errmsg = "Failed to get key features";
            goto cleanup;
        }
        if ((key_features
                & (WALLY_MS_IS_PRIVATE | WALLY_MS_IS_UNCOMPRESSED | WALLY_MS_IS_RAW | WALLY_MS_IS_X_ONLY
                    | WALLY_MS_IS_PARENTED))
            != WALLY_MS_IS_PARENTED) {
            *errmsg = "Invalid key features";
            goto cleanup;
        }

        // Fingerprint
        if (wally_descriptor_get_key_origin_fingerprint(d, i, signer->fingerprint, sizeof(signer->fingerprint))
            != WALLY_OK) {
            *errmsg = "Failed to get signer fingerprint";
            goto cleanup;
        }

        // Derivation path
        str = NULL;
        if (wally_descriptor_get_key_origin_path_str(d, i, &str) != WALLY_OK || !str) {
            *errmsg = "Failed to get derivation path string";
            goto cleanup;
        }
        const size_t derivation_path_len = sizeof(signer->derivation) / sizeof(signer->derivation[0]);
        if (!wallet_bip32_path_from_str(
                str, strlen(str), signer->derivation, derivation_path_len, &signer->derivation_len)) {
            *errmsg = "Failed to parse derivation path string";
            JADE_WALLY_VERIFY(wally_free_string(str));
            goto cleanup;
        }
        JADE_WALLY_VERIFY(wally_free_string(str));

        // xpub / key
        str = NULL;
        if (wally_descriptor_get_key(d, i, &str) != WALLY_OK || !str) {
            *errmsg = "Failed to get key/xpub string";
            goto cleanup;
        }
        const size_t xpub_len = strlen(str);
        if (xpub_len >= sizeof(signer->xpub)) {
            *errmsg = "Failed to get key xpub string";
            JADE_WALLY_VERIFY(wally_free_string(str));
            goto cleanup;
        }
        strcpy(signer->xpub, str);
        signer->xpub_len = xpub_len;
        JADE_WALLY_VERIFY(wally_free_string(str));

        // Child path (as string)
        str = NULL;
        if (wally_descriptor_get_key_child_path_str(d, i, &str) != WALLY_OK || !str) {
            *errmsg = "Failed to get child path string";
            goto cleanup;
        }
        strcpy(signer->path_str, str);
        signer->path_len = strlen(str);
        signer->path_is_string = true;
        JADE_WALLY_VERIFY(wally_free_string(str));
    }

    // Return the number of signers written
    *written = num_keys;
    retval = true;

cleanup:
    JADE_WALLY_VERIFY(wally_descriptor_free(d));
    return retval;
}

// On success output must be freed with wally_free_string()
bool descriptor_to_address(const char* name, const descriptor_data_t* descriptor, const char* network,
    const uint32_t multi_index, const uint32_t child_num, descriptor_type_t* deduced_type, char** output,
    const char** errmsg)
{
    JADE_ASSERT(name);
    JADE_ASSERT(descriptor);
    JADE_ASSERT(network);
    JADE_ASSERT(!deduced_type || *deduced_type == DESCRIPTOR_TYPE_UNKNOWN);
    JADE_INIT_OUT_PPTR(output);
    JADE_INIT_OUT_PPTR(errmsg);

    struct wally_descriptor* d = NULL;
    uint32_t depth = 0;
    if (!parse_descriptor(name, descriptor, network, deduced_type, &d, &depth, errmsg)) {
        JADE_ASSERT(!d);
        return false;
    }

    // Get address - note 'large stack' workaround as it can require many kb of
    // stack space for all but the simplest miniscript descriptors, and we don't
    // want to assume anything about the free stack at the time of calling.
    const size_t stack_size = DESCRIPTOR_PARSE_STACK_SIZE(depth);
    descriptor_evaluation_data_t args
        = { .descriptor = d, .multi_index = multi_index, .child_num = child_num, .addr_output = NULL };
    const bool ret = run_in_temporary_task(stack_size, descriptor_to_address_impl, &args);
    JADE_WALLY_VERIFY(wally_descriptor_free(d));

    if (!ret || !args.addr_output) {
        JADE_LOGE("Descriptor '%s' failed to generate address for %lu/%lu: %d", name, multi_index, child_num, ret);
        *errmsg = "Failed to obtain address from descriptor";
        return false;
    }

    // Address generated - caller takes ownership
    *output = args.addr_output;
    return true;
}

// On success output must be freed
// NOTE: For miniscript expressions, the script generated is untyped bitcoin script.
//       For descriptors, a scriptPubKey is generated.
bool descriptor_to_script(const char* name, const descriptor_data_t* descriptor, const char* network,
    const uint32_t multi_index, const uint32_t child_num, descriptor_type_t* deduced_type, uint8_t** output,
    size_t* output_len, const char** errmsg)
{
    JADE_ASSERT(name);
    JADE_ASSERT(descriptor);
    JADE_ASSERT(network);
    JADE_ASSERT(!deduced_type || *deduced_type == DESCRIPTOR_TYPE_UNKNOWN);
    JADE_INIT_OUT_PPTR(output);
    JADE_INIT_OUT_SIZE(output_len);
    JADE_INIT_OUT_PPTR(errmsg);

    struct wally_descriptor* d = NULL;
    uint32_t depth = 0;
    if (!parse_descriptor(name, descriptor, network, deduced_type, &d, &depth, errmsg)) {
        JADE_ASSERT(!d);
        return false;
    }

    // Get script - note 'large stack' workaround as it can require many kb of
    // stack space for all but the simplest miniscript descriptors, and we don't
    // want to assume anything about the free stack at the time of calling.
    const size_t stack_size = DESCRIPTOR_PARSE_STACK_SIZE(depth);
    descriptor_evaluation_data_t args
        = { .descriptor = d, .multi_index = multi_index, .child_num = child_num, .script_output = NULL };
    const bool ret = run_in_temporary_task(stack_size, descriptor_to_script_impl, &args);
    JADE_WALLY_VERIFY(wally_descriptor_free(d));

    if (!ret || !args.script_output) {
        JADE_LOGE("Descriptor '%s' failed to generate script for %lu/%lu: %d", name, multi_index, child_num, ret);
        *errmsg = "Failed to obtain script from descriptor";
        return false;
    }

    // Script generated - caller takes ownership
    *output = args.script_output;
    *output_len = args.script_len;
    return true;
}
