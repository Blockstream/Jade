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

#if MYNEWT_VAL(BLE_POWER_CONTROL)
#if MYNEWT_VAL(BLE_HCI_VS)

#define ESP_1M_LOW    (-70)
#define ESP_1M_HIGH   (-60)
#define ESP_2M_LOW    (-68)
#define ESP_2M_HIGH   (-58)
#define ESP_S2_LOW    (-75)
#define ESP_S2_HIGH   (-65)
#define ESP_S8_LOW    (-80)
#define ESP_S8_HIGH   (-70)
#define ESP_MIN_TIME  (15)

/* Represents the set of lower / upper values of rssi of given chip
 *
 * Lower Limit Values Range: -54 to -80
 * Upper Limit Values Range: -40 to -70
 *
 * */
struct ble_gap_set_auto_pcl_params {

    /* Connection Handle of the ACL Link */
    int16_t conn_handle;

    /* The Lower RSSI limit when 1M phy is used */
    int8_t m1_lower_limit;

    /* The Upper RSSI limit when 1M phy is used */
    int8_t m1_upper_limit;

#if MYNEWT_VAL(BLE_LL_CFG_FEAT_LE_2M_PHY)
    /* The Lower RSSI limit when 2M phy is used */
    int8_t m2_lower_limit;

    /* The Upper RSSI limit when 2M phy is used */
    int8_t m2_upper_limit;
#endif

#if MYNEWT_VAL(BLE_LL_CFG_FEAT_LE_CODED_PHY)
     /* The Lower RSSI limit when S2 Coded phy is used */
    int8_t s2_lower_limit;

    /* The Upper RSSI limit when S2 Coded phy is used */
    int8_t s2_upper_limit;

    /* The Lower RSSI limit when S8 Coded phy is used */
    int8_t s8_lower_limit;

    /* The Upper RSSI limit when S8 Coded phy is used */
    int8_t s8_upper_limit;
#endif

    /* Number of tx/rx packets to wait before initiating the LE power control Request.
     * The default value is (min time spent variable =  (tx/rxpackets 15)).*/
    uint8_t min_time_spent;
};

/**
 * This API  is used to initiate the LE Power Control Request Procedure for the ACL connection
 * identified by the conn_handle parameter and other parameters.
 *
 * The parameters passed are used by controller for the subsquent LE Power Control Requests
 * that get initiated across all the connections.
 *
 * The Min_Time_Spent parameter indicates the number of tx/rx packets that the Controller
 * shall observe the RSSI  has crossed the threshold (upper and lower limit of active phy)
 * before the controller initiates the LE POWER CONTROL PROCEDURE in the link layer.
 *
 * @param params	  Instance of ble_gap_set_auto_pcl_params with different parameters
 *
 * @return                0 on success; nonzero on failure.
 */
int ble_gap_set_auto_pcl_param(struct ble_gap_set_auto_pcl_params *params);
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif
