#!/usr/bin/env bash

set -eo pipefail

if [ -z "${IDF_PATH}" ]; then
    pushd /opt/esp/idf && . ./export.sh && popd
fi

GDB=""
FLASH_IMAGE="/flash_image.bin"
EFUSE_IMAGE="/qemu_efuse.bin"

function usage {
    if [ -n "$1" ]; then
        echo "error: $1" >&2
    fi
    echo "Usage: ${0} [OPTIONS]"
    echo "OPTIONS:"
    echo "    --gdb                   Launch QEMU suspended and attach xtensa-esp32-elf-gdb"
    echo "    --flash-image <path>    Flash image to use (default: /flash_image.bin)"
    echo "    --efuse-image <path>    eFuse image to use (default: /qemu_efuse.bin)"
    echo "    -h | --help             Show this help message"
    if [ -n "$1" ]; then
        exit 1
    fi
    exit 0
}

while true; do
    case "$1" in
        --gdb)          GDB=1; shift ;;
        --flash-image)  FLASH_IMAGE="$2"; shift 2 ;;
        --efuse-image)  EFUSE_IMAGE="$2"; shift 2 ;;
        -h | --help)    usage ;;
        "") break ;;
        *) usage "unknown option $1" ;;
    esac
done

pkill -f qemu-system-xtensa || true

EXTRA_ARGS=""
BG=""
if [ -n "$GDB" ]; then
    EXTRA_ARGS="-s -S"
    BG="&"
fi

qemu-system-xtensa $EXTRA_ARGS -nographic \
    -machine esp32 \
    -m 4M \
    -drive file=${FLASH_IMAGE},if=mtd,format=raw \
    -nic user,model=open_eth,id=lo0,hostfwd=tcp:0.0.0.0:30122-:30122,hostfwd=tcp:0.0.0.0:30121-:30121 \
    -drive file=${EFUSE_IMAGE},if=none,format=raw,id=efuse \
    -global driver=nvram.esp32.efuse,property=drive,value=efuse \
    -serial pty $BG
    #-serial mon:stdio

if [ -n "$GDB" ]; then
    xtensa-esp32-elf-gdb /jade/build/jade.elf \
        -ex "target remote :1234" \
        -ex "monitor system_reset" \
        -ex "tb app_main" -ex "c" \
        -ex "b main.c:120"\
        -ex 'info b' -ex 'set print pretty on'
fi
