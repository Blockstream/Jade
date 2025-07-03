#ifndef UI_SIGN_TX_H_
#define UI_SIGN_TX_H_

#include "../ui.h"
#include "../utils/network.h"

typedef struct _asset_info asset_info_t;
typedef struct _asset_summary asset_summary_t;
typedef struct _output_info output_info_t;
struct wally_tx;

bool show_btc_transaction_outputs_activity(
    network_t network_id, const struct wally_tx* tx, const output_info_t* output_info);

bool show_btc_final_confirmation_activity(const network_t network_id, uint64_t fee, const char* warning_msg);

bool show_elements_transaction_outputs_activity(network_t network_id, const struct wally_tx* tx,
    const output_info_t* output_info, const asset_info_t* assets, size_t num_assets);

bool show_elements_final_confirmation_activity(
    network_t network_id, const char* title, uint64_t fee, const char* warning_msg);

bool show_elements_swap_activity(network_t network_id, bool initial_proposal, const asset_summary_t* in_sums,
    size_t num_in_sums, const asset_summary_t* out_sums, size_t num_out_sums, const asset_info_t* assets,
    size_t num_assets);

#endif /* UI_SIGN_TX_H_ */
