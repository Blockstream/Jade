#ifndef SIGN_UTILS_H_
#define SIGN_UTILS_H_

#include "process_utils.h"

typedef enum { TXTYPE_SEND_PAYMENT, TXTYPE_SWAP } TxType_t;

typedef struct _output_info {
    char message[128];
    uint8_t blinding_key[33];
    uint8_t asset_id[32];
    uint64_t value;
    uint8_t flags;
} output_info_t;

typedef struct _asset_summary {
    uint8_t asset_id[32];
    uint64_t value;
    uint64_t validated_value;
} asset_summary_t;

bool params_txn_validate(network_t network_id, bool for_liquid, const struct wally_tx* const tx, uint64_t* explicit_fee,
    const char** errmsg);

bool params_trusted_commitments(
    jade_process_t* process, const CborValue* params, const struct wally_tx* tx, commitment_t** data);

TxType_t params_additional_info(jade_process_t* process, CborValue* params, const struct wally_tx* tx, TxType_t* txtype,
    bool* is_partial, asset_summary_t** in_sums, size_t* num_in_sums, asset_summary_t** out_sums, size_t* num_out_sums);

// Returns true if commitments are present and validated correctly.
// Returns false otherwise, with errmsg set if an error occurred, or
// NULL if no commitment data was present.
bool params_commitment_data(
    CborValue* item, commitment_t* commitment, const struct wally_tx_output* const txout, const char** errmsg);

bool asset_summary_update(
    asset_summary_t* sums, size_t num_sums, const uint8_t* asset_id, size_t asset_id_len, uint64_t value);

bool asset_summary_validate(asset_summary_t* sums, size_t num_sums);

bool update_elements_outputs(
    const struct wally_tx* tx, commitment_t* commitments, output_info_t* outinfo, const char** errmsg);

bool validate_elements_outputs(network_t network_id, const struct wally_tx* tx, TxType_t txtype,
    const output_info_t* const output_info, asset_summary_t* in_sums, size_t num_in_sums, asset_summary_t* out_sums,
    size_t num_out_sums, const char** errmsg);

// Whether or not the sighash flags for a given tx/signature type is supported
bool sighash_is_supported(TxType_t txtype, uint32_t sig_type, uint32_t sighash, bool for_liquid, bool is_partial);

bool show_btc_fee_confirmation_activity(network_t network_id, const struct wally_tx* tx, const output_info_t* outinfo,
    script_flavour_t aggregate_inputs_scripts_flavour, uint64_t input_amount, uint64_t output_amount);

bool show_elements_fee_confirmation_activity(network_t network_id, const struct wally_tx* tx,
    const output_info_t* outinfo, script_flavour_t aggregate_inputs_scripts_flavour, uint64_t fees, TxType_t txtype,
    bool is_partial);

#endif /* SIGN_UTILS_H_ */
