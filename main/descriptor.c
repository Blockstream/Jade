#include "descriptor.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "storage.h"
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

// 0 - 1.0.22 - version, type, length, script, map-values, hmac
static const uint8_t CURRENT_DESCRIPTOR_RECORD_VERSION = 0;

// The smallest valid descriptor record, for sanity checking
// v0, no map values, assuming min script len 4(?)
#define MIN_DESCRIPTOR_BYTES_LEN (2 + 2 + 4 + 1 + 0 + 0)

// Stack size required for miniscript parsing.
// Allow 2k, plus 1k per 'depth' level, plus 4k for handling the
// public keys which are expected to be at the end of most branches.
#define DESCRIPTOR_PARSE_STACK_SIZE(depth) ((depth + 6) * 1024)

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
    uint32_t child_num;
    size_t search_depth;
    const uint8_t* script_input;
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

static bool descriptor_search_for_script_impl(void* ctx)
{
    JADE_ASSERT(ctx);
    descriptor_evaluation_data_t* const data = (descriptor_evaluation_data_t*)ctx;
    JADE_ASSERT(data->search_depth);
    JADE_ASSERT(data->script_input);
    JADE_ASSERT(data->script_len);

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

    if (maxlen < data->script_len) {
        JADE_LOGW("Descriptor script length too short");
        return false;
    }

    bool found = false;
    uint8_t* script = JADE_MALLOC(maxlen);
    for (const size_t end = data->child_num + data->search_depth; data->child_num < end; ++data->child_num) {
        // Build script
        size_t written = 0;
        if (wally_descriptor_to_script(data->descriptor, depth, index, variant, data->multi_index, data->child_num,
                flags, script, maxlen, &written)
                != WALLY_OK
            || !written || written > maxlen) {
            JADE_LOGE("Failed to get descriptor script");
            free(script);
            return false;
        }

        // See if generated is identical to the script passed in
        if (written == data->script_len && !memcmp(script, data->script_input, data->script_len)) {
            found = true;
            break;
        }
    }
    free(script);
    return found;
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
        if ((key_features & (WALLY_MS_IS_PRIVATE | WALLY_MS_IS_UNCOMPRESSED | WALLY_MS_IS_RAW | WALLY_MS_IS_PARENTED))
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

bool descriptor_search_for_script(const char* name, const descriptor_data_t* descriptor, const char* network,
    const uint32_t multi_index, uint32_t* child_num, const size_t search_depth, const uint8_t* script,
    const size_t script_len)
{
    JADE_ASSERT(name);
    JADE_ASSERT(descriptor);
    JADE_ASSERT(network);
    JADE_ASSERT(child_num);
    JADE_ASSERT(search_depth);
    JADE_ASSERT(script);
    JADE_ASSERT(script_len);

    const char* errmsg = NULL;
    descriptor_type_t* const deduced_type = NULL; // unused

    struct wally_descriptor* d = NULL;
    uint32_t depth = 0;
    if (!parse_descriptor(name, descriptor, network, deduced_type, &d, &depth, &errmsg)) {
        JADE_ASSERT(!d);
        return false;
    }

    // Search for script - note 'large stack' workaround as it can require many kb of
    // stack space for all but the simplest miniscript descriptors, and we don't
    // want to assume anything about the free stack at the time of calling.
    const size_t stack_size = DESCRIPTOR_PARSE_STACK_SIZE(depth);
    descriptor_evaluation_data_t args = { .descriptor = d,
        .multi_index = multi_index,
        .child_num = *child_num,
        .search_depth = search_depth,
        .script_input = script,
        .script_len = script_len };
    const bool ret = run_in_temporary_task(stack_size, descriptor_search_for_script_impl, &args);
    JADE_WALLY_VERIFY(wally_descriptor_free(d));

    // Return the updated child number and whether we found the script
    *child_num = args.child_num;
    return ret;
}

// Get total length of string values
size_t string_values_len(const string_value_t* datavalues, const size_t num_values)
{
    JADE_ASSERT(datavalues || !num_values);

    size_t len = 0;
    for (size_t i = 0; i < num_values; ++i) {
        const string_value_t* const map_entry = datavalues + i;
        len += map_entry->key_len;
        len += map_entry->value_len;
    }
    return len;
}

// Storage related functions
bool descriptor_to_bytes(descriptor_data_t* descriptor, uint8_t* output_bytes, const size_t output_len)
{
    JADE_ASSERT(descriptor);
    JADE_ASSERT(output_bytes);
    JADE_ASSERT(output_len == DESCRIPTOR_BYTES_LEN(descriptor));

    JADE_ASSERT(descriptor->script_len);
    JADE_ASSERT(descriptor->num_values <= sizeof(descriptor->values) / sizeof(descriptor->values[0]));

    // Version byte
    uint8_t* write_ptr = output_bytes;
    memcpy(write_ptr, &CURRENT_DESCRIPTOR_RECORD_VERSION, sizeof(CURRENT_DESCRIPTOR_RECORD_VERSION));
    write_ptr += sizeof(CURRENT_DESCRIPTOR_RECORD_VERSION);

    // Descriptor type
    const uint8_t type_byte = (uint8_t)descriptor->type;
    memcpy(write_ptr, &type_byte, sizeof(type_byte));
    write_ptr += sizeof(type_byte);

    // Descriptor script
    memcpy(write_ptr, &descriptor->script_len, sizeof(descriptor->script_len));
    write_ptr += sizeof(descriptor->script_len);
    memcpy(write_ptr, descriptor->script, descriptor->script_len);
    write_ptr += descriptor->script_len;

    // Any data values
    memcpy(write_ptr, &descriptor->num_values, sizeof(descriptor->num_values));
    write_ptr += sizeof(descriptor->num_values);

    for (uint8_t i = 0; i < descriptor->num_values; ++i) {
        const string_value_t* const map_entry = descriptor->values + i;

        memcpy(write_ptr, &map_entry->key_len, sizeof(map_entry->key_len));
        write_ptr += sizeof(map_entry->key_len);
        memcpy(write_ptr, map_entry->key, map_entry->key_len);
        write_ptr += map_entry->key_len;

        memcpy(write_ptr, &map_entry->value_len, sizeof(map_entry->value_len));
        write_ptr += sizeof(map_entry->value_len);
        memcpy(write_ptr, map_entry->value, map_entry->value_len);
        write_ptr += map_entry->value_len;
    }

    // Append hmac
    JADE_ASSERT(write_ptr + HMAC_SHA256_LEN == output_bytes + output_len);
    return wallet_hmac_with_master_key(output_bytes, output_len - HMAC_SHA256_LEN, write_ptr, HMAC_SHA256_LEN);
}

bool descriptor_from_bytes(const uint8_t* bytes, const size_t bytes_len, descriptor_data_t* descriptor)
{
    JADE_ASSERT(bytes);
    JADE_ASSERT(bytes_len >= MIN_DESCRIPTOR_BYTES_LEN);
    JADE_ASSERT(descriptor);

    // Check hmac first
    uint8_t hmac_calculated[HMAC_SHA256_LEN];
    if (!wallet_hmac_with_master_key(bytes, bytes_len - HMAC_SHA256_LEN, hmac_calculated, sizeof(hmac_calculated))
        || sodium_memcmp(bytes + bytes_len - HMAC_SHA256_LEN, hmac_calculated, sizeof(hmac_calculated)) != 0) {
        JADE_LOGW("Descriptor data HMAC error/mismatch");
        return false;
    }

    // Version byte
    const uint8_t* read_ptr = bytes;
    const uint8_t version = *read_ptr;
    if (version > CURRENT_DESCRIPTOR_RECORD_VERSION) {
        JADE_LOGE("Bad version byte in stored registered descriptor data");
        return false;
    }
    read_ptr += sizeof(version);

    // Descriptor type
    uint8_t type_byte;
    memcpy(&type_byte, read_ptr, sizeof(type_byte));
    descriptor->type = (descriptor_type_t)type_byte;
    read_ptr += sizeof(type_byte);

    // Descriptor script
    memcpy(&descriptor->script_len, read_ptr, sizeof(descriptor->script_len));
    if (descriptor->script_len > sizeof(descriptor->script)) {
        JADE_LOGE("Bad script_len stored registered descriptor data");
        return false;
    }
    read_ptr += sizeof(descriptor->script_len);
    memcpy(descriptor->script, read_ptr, descriptor->script_len);
    descriptor->script[descriptor->script_len] = '\0'; // Add null terminator
    read_ptr += descriptor->script_len;

    // Any data values
    memcpy(&descriptor->num_values, read_ptr, sizeof(descriptor->num_values));
    read_ptr += sizeof(descriptor->num_values);

    for (uint8_t i = 0; i < descriptor->num_values; ++i) {
        string_value_t* const map_entry = descriptor->values + i;

        memcpy(&map_entry->key_len, read_ptr, sizeof(map_entry->key_len));
        if (map_entry->key_len > sizeof(map_entry->key)) {
            JADE_LOGE("Bad key_len stored registered descriptor data");
            return false;
        }
        read_ptr += sizeof(map_entry->key_len);
        memcpy(map_entry->key, read_ptr, map_entry->key_len);
        map_entry->key[map_entry->key_len] = '\0'; // Add null terminator
        read_ptr += map_entry->key_len;

        memcpy(&map_entry->value_len, read_ptr, sizeof(map_entry->value_len));
        if (map_entry->value_len > sizeof(map_entry->value)) {
            JADE_LOGE("Bad value_len stored registered descriptor data");
            return false;
        }
        read_ptr += sizeof(map_entry->value_len);
        memcpy(map_entry->value, read_ptr, map_entry->value_len);
        map_entry->value[map_entry->value_len] = '\0'; // Add null terminator
        read_ptr += map_entry->value_len;
    }

    // Check just got the hmac (checked first, above) left in the buffer
    JADE_ASSERT(read_ptr + HMAC_SHA256_LEN == bytes + bytes_len);

    return true;
}

bool descriptor_load_from_storage(const char* descriptor_name, descriptor_data_t* output, const char** errmsg)
{
    JADE_ASSERT(descriptor_name);
    JADE_ASSERT(output);
    JADE_INIT_OUT_PPTR(errmsg);

    size_t registration_len = 0;
    uint8_t* const registration = JADE_MALLOC(MAX_DESCRIPTOR_BYTES_LEN); // Sufficient
    if (!storage_get_descriptor_registration(
            descriptor_name, registration, MAX_DESCRIPTOR_BYTES_LEN, &registration_len)) {
        *errmsg = "Cannot find named descriptor wallet";
        free(registration);
        return false;
    }

    if (!descriptor_from_bytes(registration, registration_len, output)) {
        *errmsg = "Cannot de-serialise descriptor wallet data";
        free(registration);
        return false;
    }

    // Sanity check data we are have loaded
    if (output->script_len > sizeof(output->script) || output->num_values > MAX_ALLOWED_SIGNERS) {
        *errmsg = "Descriptor wallet data invalid";
    }

    free(registration);
    return true;
}

// Get the registered descriptor record names
// Filtered to those valid for this signer
void descriptor_get_valid_record_names(
    char names[][MAX_DESCRIPTOR_NAME_SIZE], const size_t num_names, size_t* num_written)
{
    // script_type filter is optional
    JADE_ASSERT(names);
    JADE_ASSERT(num_names);
    JADE_INIT_OUT_SIZE(num_written);

    // Get registered descriptor names
    size_t num_descriptors = 0;
    if (!storage_get_all_descriptor_registration_names(names, num_names, &num_descriptors) || !num_descriptors) {
        // No registered multisig records
        return;
    }

    // Load description of each - remove ones that are not valid for this wallet
    size_t written = 0;
    for (size_t i = 0; i < num_descriptors; ++i) {
        const char* errmsg = NULL;
        descriptor_data_t descriptor_data;
        if (descriptor_load_from_storage(names[i], &descriptor_data, &errmsg)) {
            // If any previous records were not valid, move subsequent valid record names down
            if (written != i) {
                strcpy(names[written], names[i]);
            }
            ++written;
        }
    }
    *num_written = written;
}
