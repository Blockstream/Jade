#ifndef AMALGAMATED_BUILD
#include "address.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "network.h"

#include <wally_address.h>
#include <wally_script.h>

#include <stdio.h>

static const char BITCOIN_ADDRESS_URI_SCHEME[] = "bitcoin";

static void base58_addr(const uint8_t prefix, const uint8_t* script, char** output)
{
    JADE_ASSERT(script);
    JADE_INIT_OUT_PPTR(output);

    uint8_t decoded[21];
    decoded[0] = prefix;
    memcpy(decoded + 1, script, 20);
    JADE_WALLY_VERIFY(wally_base58_from_bytes(decoded, 21, BASE58_FLAG_CHECKSUM, output));
}

static void render_op_return(
    const uint8_t* script, const size_t script_len, const bool has_value, char* output, const size_t output_len)
{
    JADE_ASSERT(script);
    JADE_ASSERT(script_len > 0);
    JADE_ASSERT(script[0] == OP_RETURN);
    JADE_ASSERT(output);
    JADE_ASSERT(output_len >= 64); // sufficient to fit error 'too long' error message

    const char* opdesc = has_value ? "Burning Asset - OP_RETURN: " : "OP_RETURN: ";
    const size_t opedesc_len = strlen(opdesc);
    char* payload_hex = NULL;

    // Check data fits in output buffer, and verify push length matches data length
    if (script_len > 3 && script[1] == script_len - 2 && output_len > opedesc_len + (2 * (script_len - 2))) {
        // Skip over the opcode and length, and hexlify the payload
        JADE_WALLY_VERIFY(wally_hex_from_bytes(script + 2, script_len - 2, &payload_hex));
        const int ret = snprintf(output, output_len, "%s%s", opdesc, payload_hex);
        JADE_ASSERT(ret > 0 && ret < output_len);
        JADE_WALLY_VERIFY(wally_free_string(payload_hex));
    } else {
        // Too long (or short!) or inconsistent to display - show length and error message
        const int ret = snprintf(output, output_len, "%s<script length: %u - cannot be displayed>", opdesc, script_len);
        JADE_ASSERT(ret > 0 && ret < output_len);
    }
}

// Convert the passed btc script into an address
void script_to_address(const char* network, const uint8_t* script, const size_t script_len, const bool has_value,
    char* output, const size_t output_len)
{
    JADE_ASSERT(!isLiquidNetwork(network));
    JADE_ASSERT(output);
    JADE_ASSERT(output_len);

    int ret = 0;
    if (!script || !script_len) {
        ret = snprintf(output, output_len, "No Address");
        JADE_ASSERT(ret > 0 && ret < output_len);
        return;
    }

    size_t output_type;
    JADE_WALLY_VERIFY(wally_scriptpubkey_get_type(script, script_len, &output_type));

    char* tmp_str = NULL;
    uint8_t prefix = 0;
    const char* hrp = NULL;
    switch (output_type) {
    case WALLY_SCRIPT_TYPE_P2WPKH:
    case WALLY_SCRIPT_TYPE_P2WSH:
    case WALLY_SCRIPT_TYPE_P2TR:
        hrp = networkToBech32Hrp(network);
        JADE_ASSERT(hrp);
        JADE_WALLY_VERIFY(wally_addr_segwit_from_bytes(script, script_len, hrp, 0, &tmp_str));
        break;

    case WALLY_SCRIPT_TYPE_P2PKH:
        prefix = networkToP2PKHPrefix(network);
        base58_addr(prefix, script + 3, &tmp_str);
        break;

    case WALLY_SCRIPT_TYPE_P2SH:
        prefix = networkToP2SHPrefix(network);
        base58_addr(prefix, script + 2, &tmp_str);
        break;

    case WALLY_SCRIPT_TYPE_OP_RETURN:
        render_op_return(script, script_len, has_value, output, output_len);
        break;

    default:
        ret = snprintf(output, output_len, "Unknown Address");
        JADE_ASSERT(ret > 0 && ret < output_len);
        break;
    }

    if (tmp_str) {
        ret = snprintf(output, output_len, "%s", tmp_str);
        JADE_ASSERT(ret > 0 && ret < output_len);
        JADE_WALLY_VERIFY(wally_free_string(tmp_str));
    }
}

// Convert the passed liquid script into an address (confidential if blindng key passed)
void elements_script_to_address(const char* network, const uint8_t* script, const size_t script_len,
    const bool has_value, const uint8_t* blinding_key, const size_t blinding_key_len, char* output,
    const size_t output_len)
{
    JADE_ASSERT(isLiquidNetwork(network));
    JADE_ASSERT(output);
    JADE_ASSERT(output_len);

    int ret = 0;
    if (!script || !script_len) {
        ret = snprintf(output, output_len, "[FEE]");
        JADE_ASSERT(ret > 0 && ret < output_len);
        return;
    }

    size_t output_type = WALLY_SCRIPT_TYPE_UNKNOWN;
    JADE_WALLY_VERIFY(wally_scriptpubkey_get_type(script, script_len, &output_type));

    char* tmp_str = NULL;
    uint8_t prefix = 0;
    const char* hrp = NULL;
    switch (output_type) {
    case WALLY_SCRIPT_TYPE_P2WPKH:
    case WALLY_SCRIPT_TYPE_P2WSH:
    case WALLY_SCRIPT_TYPE_P2TR:
        hrp = networkToBech32Hrp(network);
        JADE_ASSERT(hrp);
        JADE_WALLY_VERIFY(wally_addr_segwit_from_bytes(script, script_len, hrp, 0, &tmp_str));
        break;

    case WALLY_SCRIPT_TYPE_P2PKH:
        prefix = networkToP2PKHPrefix(network);
        base58_addr(prefix, script + 3, &tmp_str);
        break;

    case WALLY_SCRIPT_TYPE_P2SH:
        prefix = networkToP2SHPrefix(network);
        base58_addr(prefix, script + 2, &tmp_str);
        break;

    case WALLY_SCRIPT_TYPE_OP_RETURN:
        render_op_return(script, script_len, has_value, output, output_len);
        break;

    default:
        // add a "[C]" prefix to show that the address is confidential
        ret = snprintf(output, output_len, "%sUnknown Address", blinding_key ? "[C] " : "");
        JADE_ASSERT(ret > 0 && ret < output_len);
        break;
    }

    if (blinding_key) {
        char* conf_tmp_str = NULL;
        const char* hrpConfidential = NULL;

        switch (output_type) {
        case WALLY_SCRIPT_TYPE_P2WPKH:
        case WALLY_SCRIPT_TYPE_P2WSH:
        case WALLY_SCRIPT_TYPE_P2TR:
            hrpConfidential = networkToBlech32Hrp(network);
            JADE_ASSERT(hrpConfidential);
            JADE_WALLY_VERIFY(wally_confidential_addr_from_addr_segwit(
                tmp_str, hrp, hrpConfidential, blinding_key, blinding_key_len, &conf_tmp_str));
            break;

        case WALLY_SCRIPT_TYPE_P2PKH:
        case WALLY_SCRIPT_TYPE_P2SH:
            prefix = networkToCAPrefix(network);
            JADE_WALLY_VERIFY(
                wally_confidential_addr_from_addr(tmp_str, prefix, blinding_key, blinding_key_len, &conf_tmp_str));
            break;
        }

        // swap the ptr
        if (conf_tmp_str) {
            JADE_WALLY_VERIFY(wally_free_string(tmp_str));
            tmp_str = conf_tmp_str;
        }
    }

    if (tmp_str) {
        ret = snprintf(output, output_len, "%s", tmp_str);
        JADE_ASSERT(ret > 0 && ret < output_len);
        JADE_WALLY_VERIFY(wally_free_string(tmp_str));
    }
}

// Convert potential uri form into raw base58 address string
static bool address_from_uri(const char* address, address_data_t* addr_data)
{
    JADE_ASSERT(address);
    JADE_ASSERT(addr_data);

    // Look for ':' and uri scheme
    const char* start = strchr(address, ':');
    const char* end = NULL;
    if (start) {
        // Check URI scheme
        if (start - address != sizeof(BITCOIN_ADDRESS_URI_SCHEME) - 1
            || strncasecmp(address, BITCOIN_ADDRESS_URI_SCHEME, sizeof(BITCOIN_ADDRESS_URI_SCHEME) - 1)) {
            // Bad URI scheme
            return false;
        }
        ++start; // after the ':'
        end = strchr(start, '?');
    } else {
        // No URI prefix, don't even look for '?' params
        start = address;
    }
    if (!end) {
        end = start + strlen(start);
    }
    JADE_ASSERT(end >= start);

    const size_t len = end - start;
    if (len >= sizeof(addr_data->address)) {
        // Address too long
        return false;
    }

    // Copy the raw address string
    strncpy(addr_data->address, start, len);
    addr_data->address[len] = '\0';
    return true;
}

static bool try_parse_address(const uint32_t trial_network_id, address_data_t* addr_data)
{
    JADE_ASSERT(addr_data);
    const char* const network = networkIdToNetwork(trial_network_id);
    int wret = WALLY_EINVAL;
    bool is_segwit = false;

    // 1. Try non- (or wrapped-) segwit.
    // Don't bother trying Bitcoin regtest since it shares a prefix with testnet
    if (trial_network_id != WALLY_NETWORK_BITCOIN_REGTEST) {
        wret = wally_address_to_scriptpubkey(
            addr_data->address, trial_network_id, addr_data->script, sizeof(addr_data->script), &addr_data->script_len);
    }

    if (wret != WALLY_OK) {
        // 2. Try native segwit
        wret = wally_addr_segwit_to_bytes(addr_data->address, networkToBech32Hrp(network), 0, addr_data->script,
            sizeof(addr_data->script), &addr_data->script_len);
        is_segwit = wret == WALLY_OK;
    }

    if (wret == WALLY_OK) {
        JADE_LOGI("Address %s, %ssegwit-native for %s", addr_data->address, is_segwit ? "" : "non-", network);
        JADE_ASSERT(addr_data->script_len <= sizeof(addr_data->script));
        addr_data->network_id = trial_network_id;
        return true;
    }

    // Return false if neither attempt succeeded
    return false;
}

// Try to parse a BTC address and extract the scriptpubkey or witness program
// NOTE: elements is not supported atm
bool parse_address(const char* address, address_data_t* addr_data)
{
    JADE_ASSERT(address);
    JADE_ASSERT(addr_data);

    addr_data->address[0] = '\0';
    addr_data->network_id = WALLY_NETWORK_NONE;
    addr_data->script_len = 0;

    // Convert potential uri form into raw base58 address string
    if (!address_from_uri(address, addr_data)) {
        // Bad address uri format
        return false;
    }

    // Try to parse the passed address for mainnet, testnet and localtest/regtest
    if (try_parse_address(WALLY_NETWORK_BITCOIN_MAINNET, addr_data)
        || try_parse_address(WALLY_NETWORK_BITCOIN_TESTNET, addr_data)
        || try_parse_address(WALLY_NETWORK_BITCOIN_REGTEST, addr_data)) {
        // Script parsed
        const size_t len = strnlen(addr_data->address, sizeof(addr_data->address));
        JADE_ASSERT(len > 0 && len < sizeof(addr_data->address));
        JADE_ASSERT(addr_data->network_id != WALLY_NETWORK_NONE);
        JADE_ASSERT(addr_data->script_len);
        return true;
    }

    return false;
}
#endif // AMALGAMATED_BUILD
