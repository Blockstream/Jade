#!/usr/bin/env bash
set -eo pipefail

if [[ -z ${JADESERIALPORT} ]]; then
    echo "Serial port \"${JADESERIALPORT}\" isn't valid, using defaults"
    if [ "$(uname)" == "Darwin" ]; then
        JADESERIALPORT=/dev/cu.SLAB_USBtoUART
    elif [ -c /dev/ttyUSB0 ]; then
        JADESERIALPORT=/dev/ttyUSB0
    else
        JADESERIALPORT=/dev/ttyACM0
    fi
    echo "Serial port set to default \"${JADESERIALPORT}\""
fi

TARGET_CHIP=${1:-esp32}
BUILD_DIR=build
SKIP_ARGS=$2

if [ "$TARGET_CHIP" = "esp32" ]; then
    python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip ${TARGET_CHIP} --port ${JADESERIALPORT} --baud 2000000 --before default_reset erase_flash
    python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip ${TARGET_CHIP} --port ${JADESERIALPORT} --baud 2000000 --before default_reset --after hard_reset write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect 0xE000 ${BUILD_DIR}/ota_data_initial.bin 0x1000 ${BUILD_DIR}/bootloader/bootloader.bin 0x10000 ${BUILD_DIR}/jade.bin 0x9000 ${BUILD_DIR}/partition_table/partition-table.bin
else
    python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip ${TARGET_CHIP} --port ${JADESERIALPORT} --baud 460800 --before default_reset erase_flash
    python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip ${TARGET_CHIP} --port ${JADESERIALPORT} --baud 460800 --before=default_reset --after=hard_reset write_flash --flash_mode dio --flash_freq 80m --flash_size 8MB 0x0 ${BUILD_DIR}/bootloader/bootloader.bin 0x20000 ${BUILD_DIR}/jade.bin 0x8000 ${BUILD_DIR}/partition_table/partition-table.bin 0x1a000 ${BUILD_DIR}/ota_data_initial.bin
fi

sleep 1


if fgrep -qs "CONFIG_APPTRACE_GCOV_ENABLE=y" ${BUILD_DIR}/sdkconfig sdkconfig; then
    cleanup() {
        killall -9 openocd || true
    }

    trap cleanup EXIT ERR
    killall -9 openocd || true
    # idf.py openocd already needs to do reconfigure but in background could mess things up
    idf.py reconfigure
    idf.py openocd &

    # this takes a while on CI because it will want to rebuild things to start openocd
    # Wait up to 20 minutes (1200 seconds) for openocd to start
    for i in {1..1200}; do
        if pgrep openocd > /dev/null; then
            echo "openocd is running"
            break
        fi
        if ! jobs %% >/dev/null; then
            echo "idf.py openocd failed"
            exit 1
        fi
        sleep 1
    done

    if ! pgrep openocd > /dev/null; then
        echo "openocd did not start within 20 minutes"
        exit 1
    fi
fi

if [ -r ~/venv3/bin/activate ]; then
    # Assume we are running under the CI: pinserver requirements are already installed
    source ~/venv3/bin/activate
else
    # Install and activate a local venv
    if [ ! -r ./venv3/bin/activate ]; then
        virtualenv -p python3 venv3
    fi
    source ./venv3/bin/activate
    pip install -r pinserver/requirements.txt
fi
pip install --require-hashes -r requirements.txt

# NOTE: tools/fwprep.py should have run in the build step and produced the compressed firmware file
if [ ! -x /usr/bin/bt-agent ]; then
    echo "bt-agent not available, skipping bluetooth OTA"
    SKIP_ARGS="--skipble"
fi
FW_FULL=$(ls ${BUILD_DIR}/*_fw.bin)
python jade_ota.py --push-mnemonic --log=INFO --serialport=${JADESERIALPORT} --fwfile=${FW_FULL} ${SKIP_ARGS}

sleep 5
python -c "from jadepy import JadeAPI; jade = JadeAPI.create_serial(device=\"${JADESERIALPORT}\", timeout=5) ; jade.connect(); jade.drain(); jade.disconnect()"

python test_jade.py --log=INFO --serialport=${JADESERIALPORT} ${SKIP_ARGS}

# check if gcov is enabled and run collection tool
if fgrep -qs "CONFIG_APPTRACE_GCOV_ENABLE=y" ${BUILD_DIR}/sdkconfig sdkconfig; then
  ./tools/gcov/generate_report.sh
  killall -9 openocd || true
fi

deactivate
