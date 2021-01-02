#!/usr/bin/env bash
set -eo pipefail

if [ ! -d "${FLASHROOT}" ];then
    echo "Script run with invalid FLASHROOT, unset or set to ${FLASHROOT}"
    exit 1
fi

export OUTPUTLOG=${FLASHROOT}/jadeflash.log

echo $(date) "\n" "$@" "\n" $(env) | tee -a ${OUTPUTLOG}

if [ ! -e "${DEVNAME}" ];then
    echo "Script run with invalid DEVNAME. uset or set to ${DEVNAME}" | tee -a ${OUTPUTLOG}
    exit 1
fi

echo "Device ${DEVNAME} can now be flashed" | tee -a ${OUTPUTLOG}

source ${FLASHROOT}/venv/bin/activate

COMMON_ESPTOOL_OPTIONS="--chip esp32 --port ${DEVNAME} --baud 460800 --before default_reset --after hard_reset --no-stub  write_flash --flash_mode dio --flash_freq 40m"

# add some info to the logs
esptool.py  --port ${DEVNAME} read_mac | tee -a ${OUTPUTLOG}
esptool.py  --port ${DEVNAME} flash_id | tee -a ${OUTPUTLOG}

# flash bootloader and everything else
esptool.py ${COMMON_ESPTOOL_OPTIONS} --flash_size 4MB \
-u 0x1000 ${FLASHROOT}/build/bootloader/bootloader_signed.bin \
0x9000 ${FLASHROOT}/build/partition_table/partition-table.bin 0xE000 \
${FLASHROOT}/build/ota_data_initial.bin 0x10000 ${FLASHROOT}/build/jade_signed.bin | tee -a ${OUTPUTLOG}

echo "Flashing complete for ${DEVNAME}" | tee -a ${OUTPUTLOG}
