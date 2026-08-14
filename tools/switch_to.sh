#!/usr/bin/env bash
# Switch to developing for a given Jade variant
set -e

CONFIG=""
ARCH=""
DEVELOPMENT=""
NORADIO=""
FAKEPROD=""
HEAPTRACE=""
CI=""
LOG=""
DEBUG=""
JTAG=""
PSRAM=""
UNAMALGAMATED=""
WEBDISPLAY=""
WEBDISPLAY_LARGER=""
SKIP_RECONFIGURE=""

function usage {
    if [ -n "$1" ]; then
        echo "error: $1" >&2
    fi
    echo "${0} jade|jade_v1_1|jade_v2|jade_v2c|qemu [OPTIONS]"
    echo "WARNING: THIS SCRIPT IS FOR JADE DEVELOPMENT ONLY";
    echo "JADE OPTIONS:"
    echo "    --noradio    Disable Bluetooth support"
    echo "    --fakeprod    Prod-like build with secureboot (implies --debug)"
    echo "    --log        Enable logging"
    echo "    --log-cbor   Enable CBOR logging messages over the serial API"
    echo "    --log-wifi   Enable text logging over WiFi"
    echo "JADE V2 OPTIONS:"
    echo "    --jtag       Enable JTAG debugging support"
    echo "QEMU OPTIONS:"
    echo "    --psram      Emulate a device with PSRAM support"
    echo "    --webdisplay Provide a device display using a web browser"
    echo "    --webdisplay-larger Provide a larger device display for --webdisplay"
    echo "COMMON OPTIONS:"
    echo "    --dev        Development (non-production) device (mandatory for qemu)"
    echo "    --ci         Automatically execute the default UX action for CI testing"
    echo "    --debug      Enable debug message handlers for testing"
    echo "    --heaptrace  Enable standalone heap tracing diagnostics"
    echo "    --unamalgamated    Disable amalgamation of source files when building"
    echo "    --skip-reconfigure Make config changes but do not reconfigure the build"
    if [ -n "$1" ]; then
        exit 1
    fi
    exit 0
}

function have_cmd()
{
    command -v "$1" >/dev/null 2>&1
}

function set_config()
{
    sed -i "/^$1=/d" sdkconfig.defaults # Remove old value: ignore if missing
    if [ -n "$2" ]; then
        echo "$1=$2" >>sdkconfig.defaults # Add the new value
    fi
}

function remove_config()
{
    # Remove config value: error if missing
    REGEX="$1="
    if ! grep -q "$REGEX" "sdkconfig.defaults"; then
        echo "error: '$REGEX' not found in sdkconfig.defaults" >&2
        exit 1
    fi
    sed -i "/^$REGEX/d" sdkconfig.defaults
}

function remove_config_if_present()
{
    # Remove config value if present: ignore if missing
    REGEX="$1="
    if grep -q "$REGEX" "sdkconfig.defaults"; then
        sed -i "/^$REGEX/d" sdkconfig.defaults
    fi
}

while true; do
    case "$1" in
        jade)       CONFIG=$1; ARCH="esp32"; shift ;;
        jade_v1_1)  CONFIG=$1; ARCH="esp32"; shift ;;
        jade_v2)    CONFIG=$1; ARCH="esp32s3"; shift ;;
        jade_v2c)   CONFIG=$1; ARCH="esp32s3"; shift ;;
        qemu)       CONFIG=$1; ARCH="esp32"; shift ;;
        --dev)      DEVELOPMENT="y"; shift ;;
        --noradio)  NORADIO=1; shift ;;
        --fakeprod)  FAKEPROD=1; shift ;;
        --ci)       CI="1"; shift ;;
        --log)      LOG=uart; shift ;;
        --log-cbor) LOG=cbor; shift ;;
        --log-wifi) LOG=wifi; shift ;;
        --debug)    DEBUG=1; shift ;;
        --heaptrace) HEAPTRACE=1; shift ;;
        --jtag)     JTAG=1; shift ;;
        --psram)    PSRAM=1; shift ;;
        --unamalgamated) UNAMALGAMATED=1; shift ;;
        --webdisplay) WEBDISPLAY=1; shift ;;
        --webdisplay-larger) WEBDISPLAY=1; WEBDISPLAY_LARGER=1; shift ;;
        --skip-reconfigure) SKIP_RECONFIGURE=1; shift ;;
        -h | --help) usage ;;
        "") break ;;
        *) usage "unknown option ${1}" ;;
    esac
done

if [ -z "${ARCH}" ]; then
    usage "No target architecture selected"
fi

if [ "$CONFIG" = "qemu" ]; then
    # QEMU
    if [ -n "$NORADIO" ] || [ "$LOG" = "wifi" ] || [ -n "$DEBUG" ] || [ -n "$JTAG" ]; then
        usage "--[noradio|log-wifi|debug|jtag] must not be given for qemu"
    elif [ -n "$WEBDISPLAY" ] && [ -z "$PSRAM" ]; then
        usage "--[webdisplay|webdisplay-larger] require --psram"
    fi
else
    # Jade v1.0, 1.1, or 2.0
    if [ -n "$PSRAM" ] || [ -n "$WEBDISPLAY" ]; then
        usage "--[psram|webdisplay|webdisplay-larger] must not be given for non-qemu"
    fi
fi

if [ -n "$FAKEPROD" ] && [ -n "$DEVELOPMENT" ]; then
    usage "--fakeprod must not be given with --dev"
fi

# TODO: standardize the naming convention for prod/dev configs
if [ -n "${DEVELOPMENT}" ]; then
    if [ "$CONFIG" = "qemu" ]; then
        CONFIG_FILE="./configs/sdkconfig_${CONFIG}.defaults"
    else
        CONFIG_FILE="./configs/sdkconfig_dev_${CONFIG}.defaults"
    fi
else
    if [ "$CONFIG" = "qemu" ]; then
        usage "--dev must be given for qemu"
    fi
    CONFIG_FILE="./configs/production/sdkconfig_${CONFIG}_prod.defaults"
fi
if [ ! -f "$CONFIG_FILE" ]; then
    echo "error: config file $CONFIG_FILE does not exist" >&2
    exit 1
fi

if ! have_cmd idf.py; then
    if [ -d /opt/esp/idf ]; then
        pushd /opt/esp/idf && . ./export.sh && popd
    else
        echo "error: idf.py not found. Please install idf" >&2
        echo "\(or run export.sh from the idf install\) and try again" >&2
        exit 1
    fi
fi

idf.py clean && \
    rm -rf sdkconfig build

echo "============================================"
echo "using config file $CONFIG_FILE ..."
cp "$CONFIG_FILE" sdkconfig.defaults
if [ -n "$NORADIO" ]; then
    echo "updating config file for noradio ..."
    # remove settings (all)
    remove_config CONFIG_BT_ENABLED
    remove_config CONFIG_BT_NIMBLE_ATT_PREFERRED_MTU
    remove_config CONFIG_BT_NIMBLE_ENABLED
    remove_config CONFIG_BT_NIMBLE_GAP_DEVICE_NAME_MAX_LEN
    remove_config CONFIG_BT_NIMBLE_HOST_TASK_STACK_SIZE
    remove_config CONFIG_BT_NIMBLE_MAX_CONNECTIONS
    remove_config CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_EXTERNAL
    remove_config CONFIG_BT_NIMBLE_NVS_PERSIST
    remove_config CONFIG_BT_NIMBLE_ROLE_BROADCASTER
    remove_config CONFIG_BT_NIMBLE_ROLE_CENTRAL
    remove_config CONFIG_BT_NIMBLE_ROLE_OBSERVER
    remove_config CONFIG_BT_NIMBLE_SM_LEGACY
    remove_config CONFIG_BT_NIMBLE_SVC_GAP_DEVICE_NAME
    # add settings (all)
    set_config CONFIG_APP_NO_BLOBS y
    set_config CONFIG_MBEDTLS_ECP_RESTARTABLE y
    if [ "$CONFIG" = "jade" ] || [ "$CONFIG" = "jade_v1_1" ]; then
        # remove settings (Jade v1.x)
        remove_config CONFIG_BTDM_CTRL_BLE_MAX_CONN
        remove_config CONFIG_BTDM_CTRL_FULL_SCAN_SUPPORTED
        remove_config CONFIG_ESP_COEX_SW_COEXIST_ENABLE
        # add settings (Jade v1.x)
        set_config CONFIG_ESP_WIFI_IRAM_OPT n
        set_config CONFIG_ESP_WIFI_RX_IRAM_OPT n
    elif [ "$CONFIG" = "jade_v2" ] || [ "$CONFIG" = "jade_v2c" ]; then
        # remove settings (Jade v2)
        remove_config CONFIG_BT_NIMBLE_LOG_LEVEL_NONE
    else
        echo "error: unknown CONFIG: $CONFIG" >&2
        exit 1
    fi
fi
if [ -n "$CI" ]; then
    echo "updating config file for CI build ..."
    set_config CONFIG_DEBUG_UNATTENDED_CI y
    set_config CONFIG_HEAP_POISONING_COMPREHENSIVE y
    set_config CONFIG_LOG_DEFAULT_LEVEL_NONE y
fi
if [ "$LOG" = "cbor" ]; then
    echo "updating config file for CBOR logging ..."
    set_config CONFIG_LOG_CBOR y
    LOG="uart" # Enable UART logging below
elif [ "$LOG" = "wifi" ]; then
    echo "updating config file for WIFI logging ..."
    DEFAULT_SSID=""
    DEFAULT_PASSWORD=""
    SHOW_DEFAULT_SSID=""
    SHOW_DEFAULT_PASSWORD=""
    if have_cmd nmcli; then
        WIFI_CONNECTED=$(nmcli -f type,state device status | awk '$1=="wifi" && $2=="connected"' || true)
        if [ -n "$WIFI_CONNECTED" ]; then
            WIFI_DETAILS=$(nmcli dev wifi show-password 2>/dev/null || true)
            DEFAULT_SSID=$(echo "$WIFI_DETAILS" | grep "SSID:" | awk -F'SSID: ' '{print $2}')
            SHOW_DEFAULT_SSID=" [${DEFAULT_SSID}]"
            DEFAULT_PASSWORD=$(echo "$WIFI_DETAILS" | grep "Password:" | awk -F'Password: ' '{print $2}')
            SHOW_DEFAULT_PASSWORD=" [${DEFAULT_PASSWORD}]"
        fi
    fi
    DEFAULT_IP="192.168.1.100"
    if have_cmd ip; then
        DEFAULT_IP=$(ip addr show $(ip route | awk '/default/ { print $5 }') | grep "inet" | head -n 1 | awk '/inet/ {print $2}' | cut -d'/' -f1 | cut -d'.' -f1,2,3)
        DEFAULT_IP="${DEFAULT_IP}.100"
    fi
    set_config CONFIG_LOG_WIFI y
    read -r -p "Enter WIFI SSID${SHOW_DEFAULT_SSID}: " SSID
    set_config CONFIG_WIFI_SSID "\"${SSID:-${DEFAULT_SSID}}\""
    read -r -p "Enter WIFI Password${SHOW_DEFAULT_PASSWORD}: " PASSWORD
    set_config CONFIG_WIFI_PASSWORD "\"${PASSWORD:-${DEFAULT_PASSWORD}}\""
    read -r -p "Enter socket server IP [${DEFAULT_IP}]: " IP
    set_config CONFIG_WIFI_LOGGER_IP "\"${IP:-${DEFAULT_IP}}\""
    read -r -p "Enter socket server PORT [8888]: " PORT
    set_config CONFIG_WIFI_LOGGER_PORT ${PORT:-8888}
    LOG="uart" # Enable UART logging below
    if [ $ARCH = "esp32" ]; then
        #  On ESP32 we run out of IRAM with WIFI logging enabled
        set_config CONFIG_FREERTOS_PLACE_FUNCTIONS_INTO_FLASH y
    fi
fi
if [ "$LOG" = "uart" ]; then
    echo "updating config file for UART logging ..."
    set_config CONFIG_LOG_DEFAULT_LEVEL_NONE n
fi
if [ -n "$DEBUG" ]; then
    echo "updating config file for debug build ..."
    set_config CONFIG_DEBUG_MODE y
fi
if [ -n "$JTAG" ]; then
    if [[ "$CONFIG" != *"jade_v2"* ]]; then
        echo "error: JTAG can only be enabled for jade_v2 variants" >&2
        exit 1
    fi
    echo "updating config file for JTAG support ..."
    set_config CONFIG_JADE_USE_USB_JTAG_SERIAL y
    set_config CONFIG_LIBC_STDIN_LINE_ENDING_LF y
    set_config CONFIG_LIBC_STDOUT_LINE_ENDING_LF y
    # setting present on PROD configs but not on DEV configs
    remove_config_if_present CONFIG_ESP_CONSOLE_NONE
    set_config CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG y
    remove_config_if_present CONFIG_USJ_ENABLE_USB_SERIAL_JTAG
fi
if [ -n "$PSRAM" ]; then
    echo "updating config file for PSRAM support ..."
    # remove settings
    remove_config CONFIG_ESP_WIFI_STATIC_TX_BUFFER
    remove_config CONFIG_ESP_WIFI_STATIC_TX_BUFFER_NUM
    # add settings
    set_config CONFIG_SPIRAM y
    set_config CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY y
    set_config CONFIG_SPIRAM_BANKSWITCH_ENABLE n
    set_config CONFIG_SPIRAM_MEMTEST n
    if [ -n "$WEBDISPLAY" ]; then
        echo "updating config file for webdisplay build ..."
        # remove settings
        remove_config CONFIG_COMPILER_OPTIMIZATION_CHECKS_SILENT
        remove_config CONFIG_DEBUG_UNATTENDED_CI
        remove_config CONFIG_ESP_ERR_TO_NAME_LOOKUP
        remove_config CONFIG_ESP_SYSTEM_CHECK_INT_LEVEL_5
        remove_config CONFIG_LWIP_IPV6
        remove_config CONFIG_LWIP_NETIF_LOOPBACK
        remove_config CONFIG_UART_ISR_IN_IRAM
        # add settings
        set_config CONFIG_ESP_BROWNOUT_DET n
        set_config CONFIG_ESP_INT_WDT n
        set_config CONFIG_HAS_CAMERA y
        set_config CONFIG_HTTPD_MAX_REQ_HDR_LEN 4096
        set_config CONFIG_HTTPD_WS_SUPPORT y
    fi
    if [ -n "$WEBDISPLAY_LARGER" ]; then
        echo "updating config file for larger webdisplay build ..."
        # add settings
        set_config CONFIG_BOARD_TYPE_QEMU_LARGER y
        # remove settings
        remove_config CONFIG_BOARD_TYPE_QEMU
    fi
fi
if [ -n "$UNAMALGAMATED" ]; then
    echo "updating config file for unamalgamated build ..."
    set_config CONFIG_AMALGAMATED_BUILD n
fi
if [ -n "$FAKEPROD" ]; then
    echo "updating config file for fakeprod build ..."
    # Sign with the non-secret fakeprod key so the unit can always
    # be re-flashed with newly-signed firmware. A single signature is accepted
    # (CONFIG_SECURE_BOOT_V2_MIN_SIGNATURES=1).
    SIGNING_KEY="tools/fakeprod_v2.pem"
    if [ ! -f "$SIGNING_KEY" ]; then
        echo "error: fakeprod signing key $SIGNING_KEY not found" >&2
        exit 1
    fi
    set_config CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES y
    set_config CONFIG_SECURE_BOOT_SIGNING_KEY "\"$SIGNING_KEY\""
    # Single in-tree key is sufficient for the dev unit
    set_config CONFIG_SECURE_BOOT_V2_MIN_SIGNATURES 1
    # Show panic backtraces instead of rebooting silently
    remove_config CONFIG_ESP_SYSTEM_PANIC_SILENT_REBOOT
    set_config CONFIG_ESP_SYSTEM_PANIC_PRINT_REBOOT y
    # Development-mode flash encryption (re-flashable)
    remove_config CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE
    set_config CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT y
    # Keep JTAG usable on the dev unit
    set_config CONFIG_SECURE_BOOT_ALLOW_JTAG y
    # Keep ROM download mode so esptool can still reflash the unit
    remove_config CONFIG_SECURE_DISABLE_ROM_DL_MODE
    # Skip the irreversible ROM-download-mode efuse write in ensure_boot_flags()
    set_config CONFIG_JADE_FAKEPROD y
    # Always enable debug mode in fakeprod
    set_config CONFIG_DEBUG_MODE y
fi
if [ -n "$HEAPTRACE" ]; then
    echo "updating config file for heap tracing ..."
    # Enable standalone heap tracing for fragmentation/leak diagnostics
    set_config CONFIG_HEAP_TRACING_STANDALONE y
    set_config CONFIG_HEAP_TRACING_STACK_DEPTH 8
fi
echo "============================================"

if [ -z "$SKIP_RECONFIGURE" ]; then
    idf.py set-target $ARCH && \
        idf.py reconfigure && \
        echo "run idf.py all to build the firmware"
fi
