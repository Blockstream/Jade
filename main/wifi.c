
#ifdef CONFIG_LOG_WIFI

#include "esp_err.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"

#include "wifi.h"

static const char* TAG = "WIFI";

#define WIFI_AUTHMODE WIFI_AUTH_OPEN
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1

static const int WIFI_RETRY_ATTEMPT = 3;
static int wifi_retry_count = 0;

static esp_netif_t* netif = NULL;
static esp_event_handler_instance_t ip_event_handler;
static esp_event_handler_instance_t wifi_event_handler;
static EventGroupHandle_t s_wifi_event_group = NULL;
#ifdef CONFIG_LOG_WIFI_EXTRA
uint32_t wifi_debug_stats[16] = { 0 };
#endif

static void ip_event_cb(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    switch (event_id) {
    case (IP_EVENT_STA_GOT_IP):
        ip_event_got_ip_t* event_ip = (ip_event_got_ip_t*)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event_ip->ip_info.ip));
        wifi_retry_count = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
        break;
    case (IP_EVENT_STA_LOST_IP):
        ESP_LOGI(TAG, "Lost IP");
        break;
    case (IP_EVENT_GOT_IP6):
        ip_event_got_ip6_t* event_ip6 = (ip_event_got_ip6_t*)event_data;
        ESP_LOGI(TAG, "Got IPv6: " IPV6STR, IPV62STR(event_ip6->ip6_info.ip));
        wifi_retry_count = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
        break;
    default:
        ESP_LOGI(TAG, "IP event not handled 0x%" PRIx32, event_id);
        break;
    }
}

static void wifi_event_cb(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    ESP_LOGI(TAG, "Handling Wi-Fi event, event code 0x%" PRIx32, event_id);

    switch (event_id) {
    case (WIFI_EVENT_WIFI_READY):
        ESP_LOGI(TAG, "Wi-Fi ready");
        break;
    case (WIFI_EVENT_SCAN_DONE):
        ESP_LOGI(TAG, "Wi-Fi scan done");
        break;
    case (WIFI_EVENT_STA_START):
        ESP_LOGI(TAG, "Wi-Fi started, connecting to AP...");
        esp_wifi_connect();
        break;
    case (WIFI_EVENT_STA_STOP):
        ESP_LOGI(TAG, "Wi-Fi stopped");
        break;
    case (WIFI_EVENT_STA_CONNECTED):
        ESP_LOGI(TAG, "Wi-Fi connected");
        break;
    case (WIFI_EVENT_STA_DISCONNECTED):
        ESP_LOGI(TAG, "Wi-Fi disconnected");
        if (wifi_retry_count < WIFI_RETRY_ATTEMPT) {
            ESP_LOGI(TAG, "Retrying to connect to Wi-Fi network...");
            esp_wifi_connect();
            wifi_retry_count++;
        } else {
            ESP_LOGI(TAG, "Failed to connect to Wi-Fi network");
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        break;
    case (WIFI_EVENT_STA_AUTHMODE_CHANGE):
        ESP_LOGI(TAG, "Wi-Fi authmode changed");
        break;
    case (WIFI_EVENT_HOME_CHANNEL_CHANGE):
        ESP_LOGI(TAG, "Wi-Fi home channel changed");
        break;
    // case (WIFI_EVENT_AP_WRONG_PASSWORD):
    //     ESP_LOGI(TAG, "Wi-Fi AP wrong password");
    //     break;
    default:
        ESP_LOGI(TAG, "Wi-Fi event not handled %" PRIu32, event_id);
        break;
    }
}

esp_err_t wifi_init(bool create_event_loop)
{
    esp_err_t err;

    s_wifi_event_group = xEventGroupCreate();
    if (s_wifi_event_group == NULL) {
        ESP_LOGE(TAG, "Failed to create Wi-Fi event group");
        return ESP_FAIL;
    }
    err = esp_netif_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize netif (%d)", err);
        return err;
    }
    if (create_event_loop) {
        err = esp_event_loop_create_default();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to create event loop (%d)", err);
            return err;
        }
    }
    esp_netif_t* netif = esp_netif_create_default_wifi_sta();
    if (netif == NULL) {
        ESP_LOGE(TAG, "Failed to create default WiFi STA interface");
        return ESP_FAIL;
    }
    err = esp_netif_dhcpc_stop(netif);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to stop DHCP client (%d)", err);
        return err;
    }
    esp_netif_ip_info_t ip_info;
    int a, b, c, d;
    if (sscanf(CONFIG_WIFI_LOGGER_IP, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        ip_info.ip.addr = esp_netif_htonl(esp_netif_ip4_makeu32(a, b, c, d));
    } else {
        ESP_LOGE(TAG, "Failed to parse static IP address: %s", CONFIG_WIFI_LOGGER_IP);
        return ESP_ERR_INVALID_ARG;
    }
    if (sscanf(CONFIG_WIFI_GATEWAY, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        ip_info.gw.addr = esp_netif_htonl(esp_netif_ip4_makeu32(a, b, c, d));
    } else {
        ESP_LOGE(TAG, "Failed to parse gateway IP address: %s", CONFIG_WIFI_GATEWAY);
        return ESP_ERR_INVALID_ARG;
    }
    ip_info.netmask.addr = esp_netif_htonl(esp_netif_ip4_makeu32(255, 255, 255, 0));
    err = esp_netif_set_ip_info(netif, &ip_info);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set static IP info (%d)", err);
        return err;
    }
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    err = esp_wifi_init(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize WiFi (%d)", err);
        return err;
    }

    err = esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_cb, NULL, &wifi_event_handler);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register WiFi event handler (%d)", err);
        return err;
    }

    err = esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID, &ip_event_cb, NULL, &ip_event_handler);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register IP event handler (%d)", err);
        return err;
    }

    return ESP_OK;
}

esp_err_t wifi_free(void)
{
    esp_err_t err;

    if (s_wifi_event_group) {
        vEventGroupDelete(s_wifi_event_group);
        s_wifi_event_group = NULL;
    }

    err = esp_wifi_deinit();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to deinitialize WiFi (%d)", err);
        return err;
    }
    err = esp_wifi_clear_default_wifi_driver_and_handlers(netif);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to clear default WiFi driver and handlers (%d)", err);
        return err;
    }
    esp_netif_destroy_default_wifi(netif);
    netif = NULL;
    err = esp_event_loop_delete_default();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to delete event loop (%d)", err);
        return err;
    }

    err = esp_event_handler_instance_unregister(IP_EVENT, ESP_EVENT_ANY_ID, ip_event_handler);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to unregister IP event handler (%d)", err);
        return err;
    }
    err = esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to unregister Wi-Fi event handler (%d)", err);
        return err;
    }

    return ESP_OK;
}

esp_err_t wifi_connect(const char* wifi_ssid, const char* wifi_password)
{
    esp_err_t err;

    wifi_config_t wifi_config = {
        .sta = {
            // this sets the weakest authmode accepted in fast scan mode (default)
            .threshold.authmode = WIFI_AUTHMODE,
        },
    };

    strncpy((char*)wifi_config.sta.ssid, wifi_ssid, sizeof(wifi_config.sta.ssid));
    strncpy((char*)wifi_config.sta.password, wifi_password, sizeof(wifi_config.sta.password));

    err = esp_wifi_set_ps(WIFI_PS_NONE); // default is WIFI_PS_MIN_MODEM
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set Wi-Fi power save mode (%d)", err);
        return err;
    }
    err = esp_wifi_set_storage(WIFI_STORAGE_RAM); // default is WIFI_STORAGE_FLASH
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set Wi-Fi storage (%d)", err);
        return err;
    }

    err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set Wi-Fi mode (%d)", err);
        return err;
    }
    err = esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set Wi-Fi config (%d)", err);
        return err;
    }

    ESP_LOGI(TAG, "Connecting to Wi-Fi network: %s", wifi_config.sta.ssid);
    err = esp_wifi_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start Wi-Fi (%d)", err);
        return err;
    }

    EventBits_t bits
        = xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT, pdFALSE, pdFALSE, portMAX_DELAY);

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to Wi-Fi network: %s", wifi_config.sta.ssid);
        return ESP_OK;
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(TAG, "Failed to connect to Wi-Fi network: %s", wifi_config.sta.ssid);
        return ESP_FAIL;
    }

    ESP_LOGE(TAG, "Unexpected Wi-Fi error");
    return ESP_FAIL;
}

esp_err_t wifi_disconnect(void)
{
    esp_err_t err;

    err = esp_wifi_disconnect();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to disconnect from Wi-Fi (%d)", err);
    }

    err = esp_wifi_stop();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to stop Wi-Fi (%d)", err);
        return err;
    }

    return ESP_OK;
}

#define SERVER_BUFFER_SIZE 1024
static SemaphoreHandle_t socket_mutex = NULL;
static SemaphoreHandle_t socket_signal = NULL;
static bool socket_exit;
static bool socket_listening;
static int sock;
TaskHandle_t socket_task = NULL;

static void socket_server_task(void* arg)
{
    int addr_family = AF_INET;
    struct sockaddr_in dest_addr;
    int keep_alive = 1;
    int keep_alive_idle_time = 5;
    int keep_alive_time_interval = 5;
    int keep_alive_attempts = 5;
    struct sockaddr_storage source_addr;
    socklen_t addr_len = sizeof(source_addr);
    char addr_str[128] = { 0 };

    bool client_connected = false;

    // configure address and port
    dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(CONFIG_WIFI_LOGGER_PORT);

    // create socket
    int listen_sock = socket(addr_family, SOCK_STREAM, IPPROTO_IP);
    if (listen_sock < 0) {
        ESP_LOGE(TAG, "Error: failed to create TCP socket. Error code: %d", errno);
        // send first signal that socket_listening is not set
        xSemaphoreGive(socket_signal);
        goto cleanup;
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // bind
    if (bind(listen_sock, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) != 0) {
        ESP_LOGE(TAG, "Error: failed to bind TCP socket server. Error code: %d", errno);
        ESP_LOGE(TAG, "IPPROTO: %d", addr_family);
        // send first signal that socket_listening is not set
        xSemaphoreGive(socket_signal);
        goto cleanup;
    }
    ESP_LOGI(TAG, "Socket server bound, port %d", CONFIG_WIFI_LOGGER_PORT);

    // listen
    if (listen(listen_sock, 1) != 0) {
        ESP_LOGE(TAG, "Error: failed to enter in the listen state. Error code: %d", errno);
        // send first signal that socket_listening is not set
        xSemaphoreGive(socket_signal);
        goto cleanup;
    }
    ESP_LOGI(TAG, "Socket server listening");

    // set non-blocking mode
    int flags = fcntl(listen_sock, F_GETFL);
    fcntl(listen_sock, F_SETFL, flags | O_NONBLOCK);

    // communicate that we succeeded (created/bound/listen) the socket
    xSemaphoreTake(socket_mutex, portMAX_DELAY);
    socket_listening = true;
    xSemaphoreGive(socket_mutex);
    // send first signal that socket_listening is set
    xSemaphoreGive(socket_signal);

    client_connected = false;
    while (1) {
        xSemaphoreTake(socket_mutex, portMAX_DELAY);
        const bool exit = socket_exit;
        xSemaphoreGive(socket_mutex);
        if (exit) {
            break;
        }

        if (!client_connected) {
            xSemaphoreTake(socket_mutex, portMAX_DELAY);

            // accept new client connection
            sock = accept(listen_sock, (struct sockaddr*)&source_addr,
                &addr_len); // we set non-blocking mode so should not block here
            if (sock >= 0) {
                // client connected, set keep-alive and non-blocking mode
                setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keep_alive, sizeof(int));
                setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &keep_alive_idle_time, sizeof(int));
                setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keep_alive_time_interval, sizeof(int));
                setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keep_alive_attempts, sizeof(int));
                int flags_client = fcntl(sock, F_GETFL);
                fcntl(sock, F_SETFL, flags_client | O_NONBLOCK);

                if (source_addr.ss_family == PF_INET) {
                    inet_ntoa_r(((struct sockaddr_in*)&source_addr)->sin_addr, addr_str, sizeof(addr_str) - 1);
                }

                client_connected = true;
            } else {
                client_connected = false;
            }

            xSemaphoreGive(socket_mutex);

            if (!client_connected) {
                vTaskDelay(10 / portTICK_PERIOD_MS);
                continue;
            }
        }
#ifdef CONFIG_LOG_WIFI_EXTRA
        char rx_buffer[SERVER_BUFFER_SIZE] = { 0 };

        // read any incoming messages
        const int recv_count = recv(sock, rx_buffer, sizeof(rx_buffer) - 1, MSG_DONTWAIT);
        if (recv_count > 0) {
            // got message
            xSemaphoreTake(socket_mutex, portMAX_DELAY);

            rx_buffer[min(recv_count, sizeof(rx_buffer) - 1)] = 0;

            // echo message back to client
            send(sock, rx_buffer, min(recv_count, sizeof(rx_buffer)), 0);

            // check for commands
            if (strncmp(rx_buffer, "exit", 4) == 0) {
                close(sock);
                sock = -1;
                client_connected = false;
            } else if (strncmp(rx_buffer, "reset", 5) == 0) {
                esp_restart();
            } else if (strncmp(rx_buffer, "dump", 4) == 0) {
                // TODO: figure out this
                // panic_info_t info;
                // esp_core_dump_write(&info);
            } else if (strncmp(rx_buffer, "stats", 5) == 0) {
                // Dump debug stats. These will only be populated if debug code
                // has been added somewhere to popuate them
                const size_t num_stats = sizeof(wifi_debug_stats) / sizeof(wifi_debug_stats[0]);
                for (size_t i = 0; i < num_stats; ++i) {
                    snprintf(rx_buffer, sizeof(rx_buffer), "%" PRIx32 ",", wifi_debug_stats[i]);
                    send(sock, rx_buffer, strlen(rx_buffer), 0);
                }
                send(sock, "\n", 1, 0);
            } else if (strncmp(rx_buffer, "tasks", 5) == 0) {
                memset(rx_buffer, 0x00, sizeof(rx_buffer));
                vTaskList(rx_buffer);
                // check for overflow before sending
                rx_buffer[sizeof(rx_buffer) - 1] = 0;
                JADE_ASSERT(strlen(rx_buffer) < sizeof(rx_buffer) - 1);
                // ok we did not overflow, send it
                send(sock, rx_buffer, strlen(rx_buffer), 0);
            } else if (strncmp(rx_buffer, "task", 4) == 0) {
                // remove new line from end of rx_buffer
                int l = strlen(rx_buffer);
                rx_buffer[min(l, sizeof(rx_buffer)) - 2] = 0;
                const char* task_name = &rx_buffer[5];
                TaskHandle_t task_handle = xTaskGetHandle(task_name);
                if (task_handle != NULL) {
                    TaskStatus_t task_status;
                    vTaskGetInfo(task_handle, &task_status, pdTRUE, eInvalid);
                    memset(rx_buffer, 0x00, sizeof(rx_buffer));
                    snprintf(rx_buffer, sizeof(rx_buffer), "Run time counter: %ld\n", task_status.ulRunTimeCounter);
                    send(sock, rx_buffer, strlen(rx_buffer), 0);
                }
            } else if (strncmp(rx_buffer, "versions", 8) == 0) {
                const esp_partition_t* running = esp_ota_get_running_partition();
                esp_app_desc_t running_app_info;
                char* app_ver = NULL;
                if (running) {
                    // Populate the running partition info struct
                    esp_err_t err = esp_ota_get_partition_description(running, &running_app_info);
                    if (err == ESP_OK) {
                        app_ver = running_app_info.version;
                    }
                }
                memset(rx_buffer, 0x00, sizeof(rx_buffer));
                snprintf(rx_buffer, sizeof(rx_buffer), "ESP-IDF version: %s\nApp version: %s\n", IDF_VER, app_ver);
                send(sock, rx_buffer, strlen(rx_buffer), 0);
            }

            xSemaphoreGive(socket_mutex);
        }
#endif // CONFIG_LOG_WIFI_EXTRA

        vTaskDelay(10 / portTICK_PERIOD_MS);
    }

cleanup:

    if (listen_sock >= 0) {
        close(listen_sock);
    }

    // send second signal that task is finished
    xSemaphoreGive(socket_signal);
}

esp_err_t socket_server_start(void)
{
    JADE_ASSERT(socket_mutex == NULL);
    JADE_ASSERT(socket_signal == NULL);
    JADE_ASSERT(socket_task == NULL);

    socket_mutex = xSemaphoreCreateMutex();
    JADE_ASSERT(socket_mutex);
    socket_signal = xSemaphoreCreateBinary();
    JADE_ASSERT(socket_signal);
    socket_exit = false;
    socket_listening = false;
    sock = -1;

    BaseType_t retval = xTaskCreatePinnedToCore(socket_server_task, "socket_server", 4096, NULL, 3, &socket_task, 1);
    if (retval != pdPASS) {
        ESP_LOGE(TAG, "Failed to create TCP socket server task, xTaskCreatePinnedToCore() returned %d", retval);
        socket_server_stop();
        return ESP_FAIL;
    }

    // wait for first signal that socket_listening is/not set
    xSemaphoreTake(socket_signal, portMAX_DELAY);
    xSemaphoreTake(socket_mutex, portMAX_DELAY);
    bool listening = socket_listening;
    xSemaphoreGive(socket_mutex);

    if (!listening) {
        ESP_LOGE(TAG, "TCP socket server task failed to create socket and or get it to the listening state");
        socket_server_stop();
        return ESP_FAIL;
    }

    return ESP_OK;
}

void socket_server_stop(void)
{
    JADE_ASSERT(socket_mutex);
    JADE_ASSERT(socket_signal);
    JADE_ASSERT(socket_task);

    xSemaphoreTake(socket_mutex, portMAX_DELAY);
    socket_exit = true;
    xSemaphoreGive(socket_mutex);

    if (socket_task) {
        // wait for second signal that task is finished
        xSemaphoreTake(socket_signal, portMAX_DELAY);
        vTaskDelete(socket_task);
        socket_task = NULL;
    }

    vSemaphoreDelete(socket_mutex);
    socket_mutex = NULL;
    vSemaphoreDelete(socket_signal);
    socket_signal = NULL;
}

void socket_server_send(const char* message, int message_len)
{
    JADE_ASSERT(socket_mutex);
    xSemaphoreTake(socket_mutex, portMAX_DELAY);
    if (sock <= 0) {
        // no client connected
        xSemaphoreGive(socket_mutex);
        return;
    }
    send(sock, message, message_len, 0);
    xSemaphoreGive(socket_mutex);
}

// Convienience function to init WIFI, connect, and start socket server for logging
esp_err_t wifi_socket_server_logger_start(void)
{
    esp_err_t err = wifi_init(false);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize Wi-Fi (%d)", err);
        return err;
    } else {
        ESP_LOGI(TAG, "Wi-Fi initialized successfully");
    }
    ESP_LOGI(TAG, "Connecting to Wi-Fi SSID: %s, Password: %s", CONFIG_WIFI_SSID, CONFIG_WIFI_PASSWORD);
    err = wifi_connect(CONFIG_WIFI_SSID, CONFIG_WIFI_PASSWORD);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to connect to Wi-Fi (%d)", err);
        return err;
    } else {
        ESP_LOGI(TAG, "Wi-Fi connected successfully");
    }
    err = socket_server_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start the socket server");
        return err;
    } else {
        ESP_LOGI(TAG, "Socket server started");
    }
    return ESP_OK;
}

#endif // CONFIG_LOG_WIFI
