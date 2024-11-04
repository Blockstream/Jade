#ifndef AMALGAMATED_BUILD
#include "power.h"
#include "jade_assert.h"
#include <sdkconfig.h>

// Include implementation specific to hardware and/or power management chip

#if defined(CONFIG_BOARD_TYPE_JADE)
#include "power/jadev10.inc"
#elif defined(CONFIG_BOARD_TYPE_JADE_V1_1)
#include "power/jadev11.inc"
#elif defined(CONFIG_BOARD_TYPE_JADE_V2)
#include "power/jadev20.inc"
#elif defined(CONFIG_BOARD_TYPE_M5_STICKC_PLUS) || defined(CONFIG_BOARD_TYPE_M5_CORE2)
// These have AXP192 but configured differently from the Jade
#include "power/m5stickcplus.inc"
#elif defined(CONFIG_BOARD_TYPE_M5_STICKC_PLUS_2)
// Board with IP5303 Power PMU
#include "power/m5stickcplus2.inc"
#elif defined(CONFIG_BOARD_TYPE_M5_CORES3)
// M5 Core S3 has AXP2101
#include "power/m5stackcores3.inc"
#elif defined(CONFIG_BOARD_TYPE_TTGO_TWATCHS3)
// twatchs3 has AXP2101
#include "power/twatchs3.inc"
#elif defined(CONFIG_HAS_IP5306)
#include "power/ip5306.inc"
#elif defined(CONFIG_BOARD_TYPE_WS_TOUCH_LCD2)
#include "power/wslcdtouch2.inc"
#elif defined(CONFIG_BOARD_TYPE_TTGO_TDISPLAYS3) && defined(CONFIG_HAS_BATTERY)
// ttgo-tdisplays3 can read battery level and charging status if a battery is connected
#include "power/tdisplays3.inc"
#else
// Stubs for other hw boards (ie. no power management)
#include "power/minimal.inc"
#endif
#endif // AMALGAMATED_BUILD
