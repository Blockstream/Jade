#ifndef _LIBJADE_SDKCONFIG_H_
#define _LIBJADE_SDKCONFIG_H_ 1

// Config defines for a software Jade device

// Export debug mode functions for testing
#define CONFIG_DEBUG_MODE 1

// Auto "press" OK buttons when tasks are run (after 1ms)
#define CONFIG_DEBUG_UNATTENDED_CI 1
#define CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS 1

// Default to no logging
#define CONFIG_LOG_DEFAULT_LEVEL_NONE

// Tell the firmware code we are building libjade
#define CONFIG_LIBJADE 1

// libjade currently has no GUI support
#define CONFIG_LIBJADE_NO_GUI 1

// Users can define CONFIG_LIBJADE_NO_SPIRAM to disable SPIRAM emulation
// (e.g. to allow testing DIY devices)
#ifndef CONFIG_LIBJADE_NO_SPIRAM
#define CONFIG_SPIRAM 1
#endif // CONFIG_LIBJADE_NO_SPIRAM

// Provide values in order to compile (we don't actually have a screen)
// FIXME: Allow defaulting to the values for Jade v1 and v2
#define CONFIG_DISPLAY_WIDTH 320
#define CONFIG_DISPLAY_HEIGHT 200
#define CONFIG_DISPLAY_OFFSET_X 0
#define CONFIG_DISPLAY_OFFSET_Y 0
#define CONFIG_DISPLAY_FULL_FRAME_BUFFER 1
#define CONFIG_DISPLAY_FULL_FRAME_BUFFER_DOUBLE 1

// libjade has no camera, but supports the debug scan_qr message
#define CONFIG_HAS_CAMERA 1

#define CONFIG_IDF_FIRMWARE_CHIP_ID 0 // Needed to build

#endif // _LIBJADE_SDKCONFIG_H_
