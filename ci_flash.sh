#!/bin/bash
set -eo pipefail

if [[ -z ${JADESERIALPORT} ]]; then
    echo "Serial port \"${JADESERIALPORT}\" isn't valid, using defaults"
    if [ "$(uname)" == "Darwin" ]; then
        JADESERIALPORT=/dev/cu.SLAB_USBtoUART
    else
        JADESERIALPORT=/dev/ttyUSB0
    fi
    echo "Serial port set to default \"${JADESERIALPORT}\""
fi

# Deduce a port for the pinserver and redis.  Slightly hacky.
SUFFIX="${JADESERIALPORT: -1}"
if [ "${SUFFIX}" -gt "0" ] 2> /dev/null
then
    PINSVRPORT="500${SUFFIX}"
    REDIS_PORT="600${SUFFIX}"
else
    PINSVRPORT="5000"
    REDIS_PORT="6000"
fi

python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip esp32 --port ${JADESERIALPORT} --baud 2000000 --before default_reset erase_flash

python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip esp32 --port ${JADESERIALPORT} --baud 2000000 --before default_reset --after hard_reset write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect 0xE000 build/ota_data_initial.bin 0x1000 build/bootloader/bootloader.bin 0x10000 build/jade.bin 0x9000 build/partition_table/partition-table.bin

sleep 1

source ~/venv3/bin/activate

pip install --require-hashes -r requirements.txt -r pinserver/requirements.txt

PINSERVER_PORT="${PINSVRPORT}" python -m unittest -v

if command -v redis-server &> /dev/null
then
    echo "Redis found, running tests on localhost:${REDIS_PORT}"
    redis-server --port ${REDIS_PORT}  &
    REDIS_HEALTH_CHECK_INTERVAL=0 REDIS_SLEEP=0 REDIS_PORT=${REDIS_PORT} REDIS_HOST='localhost' PINSERVER_PORT="${PINSVRPORT}" python -m unittest -v
    redis-cli -p ${REDIS_PORT} shutdown
fi

python jade_ota.py --push-mnemonic --log=INFO --serialport=${JADESERIALPORT}

python test_jade.py --log=INFO --serialport=${JADESERIALPORT}
