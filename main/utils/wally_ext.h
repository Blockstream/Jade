#ifndef UTILS_WALLY_EXT_H_
#define UTILS_WALLY_EXT_H_

void jade_wally_init(void);
void jade_wally_randomize_secp_ctx(void);

void jade_wally_free_tx_wrapper(void* tx);
void jade_wally_free_map_wrapper(void* map);
void jade_wally_free_psbt_wrapper(void* psbt);

#endif /* UTILS_WALLY_EXT_H_ */
