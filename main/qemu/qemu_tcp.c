#include "qemu_tcp.h"
#include "jade_assert.h"
#include "jade_tasks.h"
#include "process.h"
#include "utils/malloc_ext.h"
#include "wire.h"

#include <esp_err.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <sdkconfig.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <esp_eth.h>
#include <esp_eth_phy.h>
#include <esp_netif.h>

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

static uint8_t* full_qemu_tcp_data_in = NULL;
static uint8_t* qemu_tcp_data_out = NULL;

static esp_eth_handle_t s_eth_handle = NULL;
static esp_eth_mac_t* s_mac = NULL;
static esp_eth_phy_t* s_phy = NULL;
static void* s_eth_glue = NULL;
static const char* TAG = "jade";

static portMUX_TYPE sockmutex;
static int qemu_tcp_sock = 0;
static int qemu_tcp_listen_sock = 0;

#define QEMU_TCP_PORT 30121

// esp-event registration context
esp_event_handler_instance_t ctx_got_ip;

static void qemu_tcp_reader(void* ignore)
{
    struct sockaddr_in dest_addr;
    struct sockaddr_in* dest_addr_ip4 = (struct sockaddr_in*)&dest_addr;
    dest_addr_ip4->sin_addr.s_addr = htonl(INADDR_ANY);
    dest_addr_ip4->sin_family = AF_INET;
    dest_addr_ip4->sin_port = htons(QEMU_TCP_PORT);

    qemu_tcp_listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    JADE_ASSERT(qemu_tcp_listen_sock >= 0);
    int err = bind(qemu_tcp_listen_sock, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    JADE_ASSERT(err == 0);

    err = listen(qemu_tcp_listen_sock, 1);
    JADE_ASSERT(err == 0);

    struct sockaddr_in source_addr;
    socklen_t addr_len = sizeof(source_addr);

    size_t read = 0;
    uint8_t* const qemu_tcp_data_in = full_qemu_tcp_data_in + 1;
    TickType_t last_processing_time = 0;

    while (1) {
        portENTER_CRITICAL(&sockmutex);
        // if we are connected we reuse it
        int tmp_qemu_tcp_sock = qemu_tcp_sock;
        portEXIT_CRITICAL(&sockmutex);

        if (tmp_qemu_tcp_sock == 0) {
            // otherwise we wait for a new connection (note: this server supports only one client at the time)
            tmp_qemu_tcp_sock = accept(qemu_tcp_listen_sock, (struct sockaddr*)&source_addr, &addr_len);
            JADE_ASSERT(tmp_qemu_tcp_sock > 0);
            portENTER_CRITICAL(&sockmutex);
            qemu_tcp_sock = tmp_qemu_tcp_sock;
            portEXIT_CRITICAL(&sockmutex);
        }

        // Read incoming data max to fill buffer
        const int len = recv(tmp_qemu_tcp_sock, qemu_tcp_data_in + read, MAX_INPUT_MSG_SIZE - read, 0);

        if (len <= 0) {
            // Close socket, pause and retry... will be reopened by above next loop
            JADE_LOGE("Error reading bytes from tcp stream device: %u", len);
            portENTER_CRITICAL(&sockmutex);
            qemu_tcp_sock = 0;
            portEXIT_CRITICAL(&sockmutex);
            shutdown(tmp_qemu_tcp_sock, 0);
            close(tmp_qemu_tcp_sock);
            read = 0;
            vTaskDelay(20 / portTICK_PERIOD_MS);
            continue;
        }

        // Pass to common handler
        JADE_LOGD("Passing %u+%u bytes from tcp stream to common handler", read, len);
        const bool force_reject_if_no_msg = false;
        handle_data(
            full_qemu_tcp_data_in, &read, len, &last_processing_time, force_reject_if_no_msg, qemu_tcp_data_out);
    }
}

static bool write_qemu_tcp(const uint8_t* msg, const size_t length, void* ignore)
{
    JADE_ASSERT(msg);
    JADE_ASSERT(length);

    portENTER_CRITICAL(&sockmutex);
    const int tmp_qemu_tcp_sock = qemu_tcp_sock;
    portEXIT_CRITICAL(&sockmutex);
    if (tmp_qemu_tcp_sock == 0) {
        return false;
    }
    int written = 0;
    while (written != length) {
        const int wrote = send(tmp_qemu_tcp_sock, msg + written, length - written, 0);
        if (written < 0) {
            JADE_LOGE("Error occurred during sending: errno %d", errno);
            return false;
        }
        written += wrote;
    }
    return true;
}

static void qemu_tcp_writer(void* ignore)
{
    while (1) {
        vTaskDelay(20 / portTICK_PERIOD_MS);
        while (jade_process_get_out_message(&write_qemu_tcp, SOURCE_QEMU_TCP, NULL)) {
            // process messages
        }
        xTaskNotifyWait(0x00, ULONG_MAX, NULL, portMAX_DELAY);
    }
}

static bool is_our_netif(const char* prefix, esp_netif_t* netif)
{
    return strncmp(prefix, esp_netif_get_desc(netif), strlen(prefix) - 1) == 0;
}

static void on_got_ip(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    ip_event_got_ip_t* event = (ip_event_got_ip_t*)event_data;
    if (!is_our_netif(TAG, event->esp_netif)) {
        JADE_LOGE("Got IPv4 from another interface \"%s\": ignored", esp_netif_get_desc(event->esp_netif));
        return;
    }
    JADE_LOGI("Got IPv4 event: Interface \"%s\" address: " IPSTR, esp_netif_get_desc(event->esp_netif),
        IP2STR(&event->ip_info.ip));
}

static esp_netif_t* get_example_netif_from_desc(const char* desc)
{
    esp_netif_t* netif = NULL;
    char* expected_desc;
    asprintf(&expected_desc, "%s: %s", TAG, desc);
    while ((netif = esp_netif_next(netif)) != NULL) {
        if (strcmp(esp_netif_get_desc(netif), expected_desc) == 0) {
            free(expected_desc);
            return netif;
        }
    }
    free(expected_desc);
    return netif;
}

static void eth_stop(void)
{
    esp_netif_t* eth_netif = get_example_netif_from_desc("eth");
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_ETH_GOT_IP, ctx_got_ip));
    ESP_ERROR_CHECK(esp_eth_stop(s_eth_handle));
    ESP_ERROR_CHECK(esp_eth_del_netif_glue(s_eth_glue));
    ESP_ERROR_CHECK(esp_eth_driver_uninstall(s_eth_handle));
    ESP_ERROR_CHECK(s_phy->del(s_phy));
    ESP_ERROR_CHECK(s_mac->del(s_mac));

    esp_netif_destroy(eth_netif);
}

static void eth_start(void)
{
    char* desc;
    esp_netif_inherent_config_t esp_netif_config = ESP_NETIF_INHERENT_DEFAULT_ETH();

    asprintf(&desc, "%s: %s", TAG, esp_netif_config.if_desc);
    esp_netif_config.if_desc = desc;
    esp_netif_config.route_prio = 64;
    esp_netif_config_t netif_config = { .base = &esp_netif_config, .stack = ESP_NETIF_NETSTACK_DEFAULT_ETH };
    esp_netif_t* netif = esp_netif_new(&netif_config);
    assert(netif);
    free(desc);

    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, on_got_ip, NULL, &ctx_got_ip));

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.phy_addr = 1;
    phy_config.reset_gpio_num = 5;
    phy_config.autonego_timeout_ms = 100;
    s_mac = esp_eth_mac_new_openeth(&mac_config);
    s_phy = esp_eth_phy_new_dp83848(&phy_config);

    esp_eth_config_t config = ETH_DEFAULT_CONFIG(s_mac, s_phy);
    ESP_ERROR_CHECK(esp_eth_driver_install(&config, &s_eth_handle));

    s_eth_glue = esp_eth_new_netif_glue(s_eth_handle);
    esp_netif_attach(netif, s_eth_glue);
    esp_eth_start(s_eth_handle);
    ESP_ERROR_CHECK(esp_register_shutdown_handler(&eth_stop));
    JADE_LOGI("Waiting for IP(s)");
    esp_netif_t* netif_ip = NULL;
    esp_netif_ip_info_t ip;
    for (int i = 0; i < esp_netif_get_nr_of_ifs(); ++i) {
        netif_ip = esp_netif_next(netif_ip);
        if (is_our_netif(TAG, netif_ip)) {
            JADE_LOGI("Connected to %s", esp_netif_get_desc(netif_ip));
            ESP_ERROR_CHECK(esp_netif_get_ip_info(netif_ip, &ip));
            JADE_LOGI("- IPv4 address: " IPSTR, IP2STR(&ip.ip));
        }
    }
}

bool qemu_tcp_init(TaskHandle_t* qemu_tcp_handle)
{
    JADE_ASSERT(qemu_tcp_handle);
    JADE_ASSERT(!full_qemu_tcp_data_in);
    JADE_ASSERT(!qemu_tcp_data_out);

    spinlock_initialize(&sockmutex);

    ESP_ERROR_CHECK(esp_netif_init());

    // Extra byte at the start for source-id
    full_qemu_tcp_data_in = JADE_MALLOC_PREFER_SPIRAM(MAX_INPUT_MSG_SIZE + 1);
    full_qemu_tcp_data_in[0] = SOURCE_QEMU_TCP;
    qemu_tcp_data_out = JADE_MALLOC_PREFER_SPIRAM(MAX_OUTPUT_MSG_SIZE);

    BaseType_t retval = xTaskCreatePinnedToCore(
        &qemu_tcp_reader, "qemu_tcp_reader", 2 * 1024, NULL, JADE_TASK_PRIO_READER, NULL, JADE_CORE_SECONDARY);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create qemu_tcp_reader task, xTaskCreatePinnedToCore() returned %d", retval);

    retval = xTaskCreatePinnedToCore(&qemu_tcp_writer, "qemu_tcp_writer", 2 * 1024, NULL, JADE_TASK_PRIO_WRITER,
        qemu_tcp_handle, JADE_CORE_SECONDARY);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create qemu_tcp_writer task, xTaskCreatePinnedToCore() returned %d", retval);
    eth_start();
    return true;
}
