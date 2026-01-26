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

# Reset the device and then flash the ble-enabled variant
if [ "$TARGET_CHIP" = "esp32" ]; then
    python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip ${TARGET_CHIP} --port ${JADESERIALPORT} --baud 2000000 --before default_reset erase_flash
    python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip ${TARGET_CHIP} --port ${JADESERIALPORT} --baud 2000000 --before default_reset --after hard_reset write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect 0xE000 ${BUILD_DIR}/ota_data_initial.bin 0x1000 ${BUILD_DIR}/bootloader/bootloader.bin 0x10000 ${BUILD_DIR}/jade.bin 0x9000 ${BUILD_DIR}/partition_table/partition-table.bin
else
    python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip ${TARGET_CHIP} --port ${JADESERIALPORT} --baud 460800 --before default_reset erase_flash
    python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip ${TARGET_CHIP} --port ${JADESERIALPORT} --baud 460800 --before=default_reset --after=hard_reset write_flash --flash_mode dio --flash_freq 80m --flash_size 8MB 0x0 ${BUILD_DIR}/bootloader/bootloader.bin 0x20000 ${BUILD_DIR}/jade.bin 0x8000 ${BUILD_DIR}/partition_table/partition-table.bin 0x1a000 ${BUILD_DIR}/ota_data_initial.bin
fi

sleep 1

# Setup the python environment
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

SKIP_SERIAL="--skipserial"
if [ "$SKIP_ARGS" = "--skipble" ]; then
    # Don't skip serial, and instead skip ble
    SKIP_SERIAL=""
else
    # Get the BLE ID from serial as this is faster
    SKIP_ARGS="--bleidfromserial"
fi

# Build the bsdiff tool in the 'tools' directory (source file in the build dir)
gcc -O2 -DBSDIFF_EXECUTABLE -o ./tools/bsdiff build/bsdiff.c

# NOTE: tools/fwprep.py should have run in the build step and produced the compressed firmware files
FW_BLE=$(ls build/*_ble_*_fw.bin)
FW_NORADIO=$(ls build_noradio/*_noradio_*_fw.bin)

# Make four patches between radio and ble firmware variants
PATCHDIR=patches
mkdir -p ${PATCHDIR}

./tools/mkpatch.py ${FW_NORADIO} ${FW_NORADIO} ${PATCHDIR} --force
./tools/mkpatch.py ${FW_BLE} ${FW_BLE} ${PATCHDIR} --force
./tools/mkpatch.py ${FW_NORADIO} ${FW_BLE} ${PATCHDIR} --force  # makes both directions
sleep 2

# first we ota to noradio via ble (or serial if skipping ble)
# NOTE: the filename is of the pattern: 'final-from-base' - hence noradio*ble*patch.bin
FW_PATCH=$(ls ${PATCHDIR}/*_noradio_*_ble*_patch.bin)
cp "${FW_NORADIO}.hash" "${FW_PATCH}.hash"
python jade_ota.py --log=INFO ${SKIP_SERIAL} ${SKIP_ARGS} --serialport=${JADESERIALPORT} --fwfile=${FW_PATCH}

# then we test the same exact firmware via serial
FW_PATCH=$(ls ${PATCHDIR}/*_noradio_*_noradio*_patch.bin)
python jade_ota.py --log=INFO --skipble --serialport=${JADESERIALPORT} --fwfile=${FW_PATCH}
sleep 2

# then we test from noradio to ble via serial
# NOTE: the filename is of the pattern: 'final-from-base' - hence ble*noradio*patch.bin
FW_PATCH=$(ls ${PATCHDIR}/*_ble_*_noradio*_patch.bin)
cp "${FW_BLE}.hash" "${FW_PATCH}.hash"
python jade_ota.py --log=INFO --skipble --serialport=${JADESERIALPORT} --fwfile=${FW_PATCH}
sleep 2

# finally we test the same exact firmware via ble (or serial if skipping ble)
FW_PATCH=$(ls ${PATCHDIR}/*_ble_*_ble*_patch.bin)
python jade_ota.py --log=INFO ${SKIP_SERIAL} ${SKIP_ARGS} --serialport=${JADESERIALPORT} --fwfile=${FW_PATCH}
sleep 2
