#ifndef JADE_OTA_H_
#define JADE_OTA_H_

#include <sdkconfig.h>

// OTA chunk size - should be less that MAX_INPUT_MSG_SIZE
#define JADE_OTA_BUF_SIZE (4096)

// Some config/features compiled into the firmware

// Whether the ble/radio is configured/enabled
#ifndef CONFIG_ESP32_NO_BLOBS
#define JADE_OTA_CONFIG "BLE"
#else
#define JADE_OTA_CONFIG "NORADIO"
#endif

// Board type - Production Jade (1.0, 1.1, etc.),
// M5Stack(fire, basic etc.), TTGO, esp32 dev board, etc.
#if defined(CONFIG_BOARD_TYPE_JADE)
#define JADE_OTA_BOARD_TYPE "JADE" // Jade 1.0 (with true wheel)
#elif defined(CONFIG_BOARD_TYPE_JADE_V1_1)
#define JADE_OTA_BOARD_TYPE "JADE_V1.1" // Jade 1.1 (with jog wheel)
#elif defined(CONFIG_BOARD_TYPE_M5_FIRE)
#define JADE_OTA_BOARD_TYPE "M5FIRE"
#elif defined(CONFIG_BOARD_TYPE_M5_BLACK_GRAY)
#define JADE_OTA_BOARD_TYPE "M5BLACKGRAY"
#elif defined(CONFIG_BOARD_TYPE_M5_STICKC_PLUS)
#define JADE_OTA_BOARD_TYPE "M5STICKCPLUS"
#elif defined(CONFIG_BOARD_TYPE_TTGO_TDISPLAY)
#define JADE_OTA_BOARD_TYPE "TTGO_TDISPLAY"
#elif defined(CONFIG_BOARD_TYPE_DEV)
#define JADE_OTA_BOARD_TYPE "DEV"
#else
#define JADE_OTA_BOARD_TYPE "UNKNOWN"
#endif

// hardware 'features' could potentially be a comma-separated list
// initially it's either 'secure boot' or 'dev' ...
#ifdef CONFIG_SECURE_BOOT
#define JADE_OTA_FEATURES "SB"
#else
#define JADE_OTA_FEATURES "DEV"
#endif

#endif /* JADE_OTA_H_ */
