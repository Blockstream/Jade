#!/usr/bin/env bash
# Switch to developing for a given Jade variant
set -e

CONFIG=""
ARCH=""
DEVELOPMENT=""
NORADIO=""
CI=""
LOG=""
DEBUG=""
JTAG=""

function usage {
    echo "THIS SCRIPT IS FOR JADE DEVELOPMENT ONLY";
    echo "${0} jade|jade_v1_1|jade_v2 [--dev] [--noradio] [--ci] [--log|--log-cbor|--log-wifi] [--debug] [--jtag]";
}

function have_cmd()
{
    command -v "$1" >/dev/null 2>&1
}

function set_config()
{
    sed -i "/^$1=/d" sdkconfig.defaults # Remove any old value
    if [ -n "$2" ]; then
        echo "$1=$2" >>sdkconfig.defaults # Add the new value
    fi
}

while true; do
    case "$1" in
        jade)       CONFIG=$1; ARCH="esp32"; shift ;;
        jade_v1_1)  CONFIG=$1; ARCH="esp32"; shift ;;
        jade_v2)    CONFIG=$1; ARCH="esp32s3"; shift ;;
        --dev)      DEVELOPMENT="y"; shift ;;
        --noradio)  NORADIO="_noradio"; shift ;;
        --ci)       CI="1"; shift ;;
        --log)      LOG=uart; shift ;;
        --log-cbor) LOG=cbor; shift ;;
        --log-wifi) LOG=wifi; shift ;;
        --debug)    DEBUG=1; shift ;;
        --jtag)     JTAG=1; shift ;;
        -h | --help) usage;
            exit 0 ;;
        "") break ;;
        *) echo "error: unknown option ${1}"; usage; exit 1
    esac
done

if [ -z "${ARCH}" ]; then
    usage
    exit 1
fi

# TODO: standardize the naming convention for prod/dev configs
if [ -n "${DEVELOPMENT}" ]; then
    CONFIG_FILE="./configs/sdkconfig_dev_${CONFIG}${NORADIO}.defaults"
else
    CONFIG_FILE="./production/sdkconfig_${CONFIG}${NORADIO}_prod.defaults"
fi
if [ ! -f $CONFIG_FILE ]; then
    echo "error: config file $CONFIG_FILE does not exist"
    exit 1
fi

if ! have_cmd idf.py; then
    echo "error: idf.py not found. Please install idf"
    echo "(or run export.sh from the idf install) and try again"
    exit 1
fi

idf.py clean && \
    rm -rf sdkconfig build && \
    cp $CONFIG_FILE sdkconfig.defaults

echo "============================================"
echo "using config file $CONFIG_FILE ..."
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
    DEFAULT_IP="192.168.1.100"
    if have_cmd ip; then
        DEFAULT_IP=$(ip addr show $(ip route | awk '/default/ { print $5 }') | grep "inet" | head -n 1 | awk '/inet/ {print $2}' | cut -d'/' -f1 | cut -d'.' -f1,2,3)
        DEFAULT_IP="${DEFAULT_IP}.100"
    fi
    set_config CONFIG_LOG_WIFI y
    read -p "Enter WIFI SSID: " SSID
    set_config CONFIG_WIFI_SSID "\"$SSID\""
    read -p "Enter WIFI Password: " PASSWORD
    set_config CONFIG_WIFI_PASSWORD "\"$PASSWORD\""
    read -p "Enter socket server IP [${DEFAULT_IP}]: " IP
    set_config CONFIG_WIFI_LOGGER_IP "\"${IP:-${DEFAULT_IP}}\""
    read -p "Enter socket server PORT [8888]: " PORT
    set_config CONFIG_WIFI_LOGGER_PORT ${PORT:-8888}
    LOG="uart" # Enable UART logging below
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
        echo "error: JTAG can only be enabled for jade_v2 variants"
        exit 1
    fi
    echo "updating config file for JTAG support ..."
    set_config CONFIG_JADE_USE_USB_JTAG_SERIAL y
    set_config CONFIG_NEWLIB_STDIN_LINE_ENDING_LF y
    set_config CONFIG_NEWLIB_STDOUT_LINE_ENDING_LF y
fi
echo "============================================"

idf.py set-target $ARCH && \
    idf.py reconfigure && \
    echo "run idf.py all to build the firmware"
