#!/usr/bin/env bash
# Perform an initial flash of an esp32s3 device
# ./tools/initial_flash_esp32s3.sh <serialport>
set -eo pipefail

if [ -z "$IDF_PATH" ]; then
    get_idf
fi

python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip esp32s3 --port ${1} --baud 460800 --before default_reset erase_flash

python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip esp32s3 --port ${1} --baud 460800 --before=default_reset --after=hard_reset write_flash --flash_mode dio --flash_freq 80m --flash_size 8MB 0x0 build/bootloader/bootloader.bin 0x20000 build/jade.bin 0x8000 build/partition_table/partition-table.bin 0x1a000 build/ota_data_initial.bin
