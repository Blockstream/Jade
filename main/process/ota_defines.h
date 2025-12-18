#ifndef JADE_OTA_H_
#define JADE_OTA_H_

#include <sdkconfig.h>

// OTA chunk size - should be less that MAX_INPUT_MSG_SIZE
#define JADE_OTA_BUF_SIZE (4096)

// Some config/features compiled into the firmware

// Whether the ble/radio is configured/enabled
#ifdef CONFIG_BT_ENABLED
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
#elif defined(CONFIG_BOARD_TYPE_JADE_V2)
#define JADE_OTA_BOARD_TYPE "JADE_V2" // Jade 2 (with physical buttons)
#elif defined(CONFIG_BOARD_TYPE_JADE_V2C)
#define JADE_OTA_BOARD_TYPE "JADE_V2C" // Jade Core (Jade 2, no camera/battery)
#elif defined(CONFIG_BOARD_TYPE_M5_FIRE)
#define JADE_OTA_BOARD_TYPE "M5FIRE"
#elif defined(CONFIG_BOARD_TYPE_M5_BLACK_GRAY)
#define JADE_OTA_BOARD_TYPE "M5BLACKGRAY"
#elif defined(CONFIG_BOARD_TYPE_M5_STICKC_PLUS)
#define JADE_OTA_BOARD_TYPE "M5STICKCPLUS"
#elif defined(CONFIG_BOARD_TYPE_M5_STICKC_PLUS_2)
#define JADE_OTA_BOARD_TYPE "M5STICKCPLUS2"
#elif defined(CONFIG_BOARD_TYPE_M5_CORES3)
#define JADE_OTA_BOARD_TYPE "M5CORES3"
#elif defined(CONFIG_BOARD_TYPE_M5_CORE2)
#define JADE_OTA_BOARD_TYPE "M5CORE2"
#elif defined(CONFIG_BOARD_TYPE_TTGO_TDISPLAY)
#define JADE_OTA_BOARD_TYPE "TTGO_TDISPLAY"
#elif defined(CONFIG_BOARD_TYPE_TTGO_TDISPLAYS3)
#define JADE_OTA_BOARD_TYPE "TTGO_TDISPLAYS3"
#elif defined(CONFIG_BOARD_TYPE_TTGO_TDISPLAYS3PROCAMERA)
#define JADE_OTA_BOARD_TYPE "TTGO_TDISPLAYS3PROCAMERA"
#elif defined(CONFIG_BOARD_TYPE_WS_TOUCH_LCD2)
#define JADE_OTA_BOARD_TYPE "WAVESHARE_TOUCH_LCD2"
#elif defined(CONFIG_BOARD_TYPE_QEMU) || defined(CONFIG_BOARD_TYPE_QEMU_LARGER)
#define JADE_OTA_BOARD_TYPE "QEMU"
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
