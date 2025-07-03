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

bool get_commitment_data(
    CborValue* item, commitment_t* commitment, const struct wally_tx_output* const txout, const char** errmsg);

bool asset_summary_update(
    asset_summary_t* sums, size_t num_sums, const uint8_t* asset_id, size_t asset_id_len, uint64_t value);

bool asset_summary_validate(asset_summary_t* sums, size_t num_sums);

bool validate_elements_outputs(jade_process_t* process, network_t network_id, const struct wally_tx* tx,
    TxType_t txtype, commitment_t* commitments, output_info_t* output_info, asset_summary_t* in_sums,
    size_t num_in_sums, asset_summary_t* out_sums, size_t num_out_sums);

bool show_btc_fee_confirmation_activity(network_t network_id, const struct wally_tx* tx, const output_info_t* outinfo,
    script_flavour_t aggregate_inputs_scripts_flavour, uint64_t input_amount, uint64_t output_amount);

bool show_elements_fee_confirmation_activity(network_t network_id, const struct wally_tx* tx,
    const output_info_t* outinfo, script_flavour_t aggregate_inputs_scripts_flavour, uint64_t fees, TxType_t txtype,
    bool is_partial);

#endif /* SIGN_UTILS_H_ */
