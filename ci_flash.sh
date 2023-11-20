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
PINSVRPORT="$(python -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')"
REDIS_PORT="$(python -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')"

# Pinserver tests use a short session lifetime (for session-timeout tests)
PINSVR_SESSION_TIMEOUT=3

python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip esp32 --port ${JADESERIALPORT} --baud 2000000 --before default_reset erase_flash

python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip esp32 --port ${JADESERIALPORT} --baud 2000000 --before default_reset --after hard_reset write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect 0xE000 build/ota_data_initial.bin 0x1000 build/bootloader/bootloader.bin 0x10000 build/jade.bin 0x9000 build/partition_table/partition-table.bin

sleep 1

source ~/venv3/bin/activate

pip install --require-hashes -r requirements.txt -r pinserver/requirements.txt

SESSION_LIFETIME="${PINSVR_SESSION_TIMEOUT}" PINSERVER_PORT="${PINSVRPORT}" python -m unittest -v

if command -v redis-server &> /dev/null
then
    echo "Redis found, running tests on localhost:${REDIS_PORT}"
    redis-server --port ${REDIS_PORT}  &
    REDIS_HEALTH_CHECK_INTERVAL=0 REDIS_SLEEP=0 REDIS_PORT=${REDIS_PORT} REDIS_HOST='localhost' SESSION_LIFETIME="${PINSVR_SESSION_TIMEOUT}" PINSERVER_PORT="${PINSVRPORT}" python -m unittest -v
    redis-cli -p ${REDIS_PORT} shutdown
fi

# NOTE: tools/fwprep.py should have run in the build step and produced the compressed firmware file
FW_FULL=$(ls build/*_fw.bin)
python jade_ota.py --push-mnemonic --log=INFO --serialport=${JADESERIALPORT} --fwfile=${FW_FULL}

sleep 5
python -c "from jadepy import JadeAPI; jade = JadeAPI.create_serial(device=\"${JADESERIALPORT}\", timeout=5) ; jade.connect(); jade.drain(); jade.disconnect()"

python test_jade.py --log=INFO --serialport=${JADESERIALPORT}
