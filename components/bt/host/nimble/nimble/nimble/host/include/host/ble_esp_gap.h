/*
 * SPDX-FileCopyrightText: 2021-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

#ifndef H_BLE_ESP_GAP_
#define H_BLE_ESP_GAP_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Configure LE Data Length in controller (OGF = 0x08, OCF = 0x0022).
 *
 * @param conn_handle      Connection handle.
 * @param tx_octets        The preferred value of payload octets that the Controller
 *                         should use for a new connection (Range
 *                         0x001B-0x00FB).
 * @param tx_time          The preferred maximum number of microseconds that the local Controller
 *                         should use to transmit a single link layer packet
 *                         (Range 0x0148-0x4290).
 *
 * @return              0 on success,
 *                      other error code on failure.
 */
int ble_hs_hci_util_set_data_len(uint16_t conn_handle, uint16_t tx_octets,
                                 uint16_t tx_time);

/**
 * Read host's suggested values for the controller's maximum transmitted number of payload octets
 * and maximum packet transmission time (OGF = 0x08, OCF = 0x0024).
 *
 * @param out_sugg_max_tx_octets    The Host's suggested value for the Controller's maximum transmitted
 *                                  number of payload octets in LL Data PDUs to be used for new
 *                                  connections. (Range 0x001B-0x00FB).
 * @param out_sugg_max_tx_time      The Host's suggested value for the Controller's maximum packet
 *                                  transmission time for packets containing LL Data PDUs to be used
 *                                  for new connections. (Range 0x0148-0x4290).
 *
 * @return                          0 on success,
 *                                  other error code on failure.
 */
int ble_hs_hci_util_read_sugg_def_data_len(uint16_t *out_sugg_max_tx_octets,
                                           uint16_t *out_sugg_max_tx_time);
/**
 * Configure host's suggested maximum transmitted number of payload octets and maximum packet
 * transmission time in controller (OGF = 0x08, OCF = 0x0024).
 *
 * @param sugg_max_tx_octets    The Host's suggested value for the Controller's maximum transmitted
 *                              number of payload octets in LL Data PDUs to be used for new
 *                              connections. (Range 0x001B-0x00FB).
 * @param sugg_max_tx_time      The Host's suggested value for the Controller's maximum packet
 *                              transmission time for packets containing LL Data PDUs to be used
 *                              for new connections. (Range 0x0148-0x4290).
 *
 * @return                      0 on success,
 *                              other error code on failure.
 */
int ble_hs_hci_util_write_sugg_def_data_len(uint16_t sugg_max_tx_octets, uint16_t sugg_max_tx_time);

/**
 * Removes the address from controller's white list.
 *
 * @param addrs                 The entry to be removed from the white list.
 *
 * @return                      0 on success; nonzero on failure.
 */
int ble_gap_wl_tx_rmv(const ble_addr_t *addrs);

/**
 * Clears all addresses from controller's white list.
 *
 * @return                      0 on success; nonzero on failure.
 */
int ble_gap_wl_tx_clear(void);

#ifdef __cplusplus
}
#endif

#endif
