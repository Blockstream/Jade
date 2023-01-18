#!/usr/bin/env bash
set -eo pipefail

FLASH_IMAGE_FILE=/flash_image.bin

. /root/esp/esp-idf/export.sh

esptool.py --chip esp32 merge_bin --fill-flash-size 4MB -o ${FLASH_IMAGE_FILE} \
--flash_mode dio --flash_freq 40m --flash_size 4MB \
0x9000 build/partition_table/partition-table.bin \
0xe000 build/ota_data_initial.bin \
0x1000 build/bootloader/bootloader.bin \
0x10000 build/jade.bin

cp main/qemu/qemu_efuse.bin /qemu_efuse.bin
chmod 777 /qemu_efuse.bin ${FLASH_IMAGE_FILE}
