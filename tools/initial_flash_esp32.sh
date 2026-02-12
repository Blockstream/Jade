#!/usr/bin/env bash
# Perform an initial flash of an esp32 device
# ./tools/initial_flash_esp32.sh <serialport>
set -eo pipefail

if [ -z "$IDF_PATH" ]; then
    get_idf
fi

python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip esp32 --port ${1} --baud 2000000 --before default_reset erase_flash

python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip esp32 --port ${1} --baud 2000000 --before default_reset --after hard_reset write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect 0xE000 build/ota_data_initial.bin 0x1000 build/bootloader/bootloader.bin 0x10000 build/jade.bin 0x9000 build/partition_table/partition-table.bin
