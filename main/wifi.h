#ifndef WIFI_H_
#define WIFI_H_

#ifdef CONFIG_LOG_WIFI
esp_err_t wifi_init(bool create_event_loop);
esp_err_t wifi_free(void);
esp_err_t wifi_connect(const char* wifi_ssid, const char* wifi_password);
esp_err_t wifi_disconnect(void);
esp_err_t socket_server_start(void);
void socket_server_stop(void);
void socket_server_send(const char* message, int message_len);
esp_err_t wifi_socket_server_logger_start(void);
#endif // CONFIG_LOG_WIFI

#endif // WIFI_H_
