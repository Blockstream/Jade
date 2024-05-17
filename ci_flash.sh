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

TARGET_CHIP=${1:-esp32}

if [ "$TARGET_CHIP" = "esp32" ]; then
    python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip ${TARGET_CHIP} --port ${JADESERIALPORT} --baud 2000000 --before default_reset erase_flash
    python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip ${TARGET_CHIP} --port ${JADESERIALPORT} --baud 2000000 --before default_reset --after hard_reset write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect 0xE000 build/ota_data_initial.bin 0x1000 build/bootloader/bootloader.bin 0x10000 build/jade.bin 0x9000 build/partition_table/partition-table.bin
else
    python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip ${TARGET_CHIP} --port ${JADESERIALPORT} --baud 460800 --before default_reset erase_flash
    python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip ${TARGET_CHIP} --port ${JADESERIALPORT} --baud 460800 --before=default_reset --after=hard_reset write_flash --flash_mode dio --flash_freq 80m --flash_size 8MB 0x0 build/bootloader/bootloader.bin 0x20000 build/jade.bin 0x8000 build/partition_table/partition-table.bin 0x1a000 build/ota_data_initial.bin
fi

sleep 1


if fgrep -qs "CONFIG_APPTRACE_GCOV_ENABLE=y" build/sdkconfig sdkconfig; then
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

source ~/venv3/bin/activate

pip install --require-hashes -r requirements.txt

# NOTE: tools/fwprep.py should have run in the build step and produced the compressed firmware file
FW_FULL=$(ls build/*_fw.bin)
python jade_ota.py --push-mnemonic --log=INFO --serialport=${JADESERIALPORT} --fwfile=${FW_FULL}

sleep 5
python -c "from jadepy import JadeAPI; jade = JadeAPI.create_serial(device=\"${JADESERIALPORT}\", timeout=5) ; jade.connect(); jade.drain(); jade.disconnect()"

python test_jade.py --log=INFO --serialport=${JADESERIALPORT}

# check if gcov is enabled and run collection tool
if fgrep -qs "CONFIG_APPTRACE_GCOV_ENABLE=y" build/sdkconfig sdkconfig; then
  ./tools/gcov/generate_report.sh
  killall -9 openocd || true
fi
