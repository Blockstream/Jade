#!/usr/bin/env bash
set -eo pipefail

if [ -n "$1" ]; then
    FLASH_IMAGE_FILE="$1"
else
    FLASH_IMAGE_FILE="/flash_image.bin"
fi

if [ -n "$2" ]; then
    EFUSE_FILE="$2"
else
    EFUSE_FILE="/qemu_efuse.bin"
fi

if [ -z "${IDF_PATH}" ]; then
    pushd /opt/esp/idf && . ./export.sh && popd
fi

esptool.py --chip esp32 merge_bin --fill-flash-size 4MB -o ${FLASH_IMAGE_FILE} \
--flash_mode dio --flash_freq 40m --flash_size 4MB \
0x9000 build/partition_table/partition-table.bin \
0xe000 build/ota_data_initial.bin \
0x1000 build/bootloader/bootloader.bin \
0x10000 build/jade.bin

cp main/qemu/qemu_efuse.bin ${EFUSE_FILE}
chmod 777 ${EFUSE_FILE} ${FLASH_IMAGE_FILE}
