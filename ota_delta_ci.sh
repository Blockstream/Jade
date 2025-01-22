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

# first we reset the device
python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip esp32 --port ${JADESERIALPORT} --baud 2000000 --before default_reset erase_flash

# then we flash the ble-enabled variant
python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip esp32 --port ${JADESERIALPORT} --baud 2000000 --before default_reset --after hard_reset write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect 0xE000 build/ota_data_initial.bin 0x1000 build/bootloader/bootloader.bin 0x10000 build/jade.bin 0x9000 build/partition_table/partition-table.bin

# Setup the python environment
source ~/venv3/bin/activate
pip install --require-hashes -r requirements.txt

# Build the bsdiff tool in the 'tools' directory (source file in the build dir)
gcc -O2 -DBSDIFF_EXECUTABLE -o ./tools/bsdiff build/bsdiff.c

# NOTE: tools/fwprep.py should have run in the build step and produced the compressed firmware files
FW_BLE=$(ls build/*_ble_*_fw.bin)
FW_NORADIO=$(ls build_noblobs/*_noradio_*_fw.bin)

# Make four patches between radio and ble firmware variants
PATCHDIR=patches
mkdir -p ${PATCHDIR}

./tools/mkpatch.py ${FW_NORADIO} ${FW_NORADIO} ${PATCHDIR}
./tools/mkpatch.py ${FW_BLE} ${FW_BLE} ${PATCHDIR}
./tools/mkpatch.py ${FW_NORADIO} ${FW_BLE} ${PATCHDIR}  # makes both directions
sleep 2

# first we ota to noblob via ble
# NOTE: the filename is of the pattern: 'final-from-base' - hence noradio*ble*patch.bin
FW_PATCH=$(ls ${PATCHDIR}/*_noradio_*_ble*_patch.bin)
cp "${FW_NORADIO}.hash" "${FW_PATCH}.hash"
python jade_ota.py --log=INFO --skipserial --bleidfromserial --serialport=${JADESERIALPORT} --fwfile=${FW_PATCH}

# then we test the same exact firmware via serial
FW_PATCH=$(ls ${PATCHDIR}/*_noradio_*_noradio*_patch.bin)
python jade_ota.py --log=INFO --skipble --serialport=${JADESERIALPORT} --fwfile=${FW_PATCH}
sleep 2

# then we test from noblob to ble via serial
# NOTE: the filename is of the pattern: 'final-from-base' - hence ble*noradio*patch.bin
FW_PATCH=$(ls ${PATCHDIR}/*_ble_*_noradio*_patch.bin)
cp "${FW_BLE}.hash" "${FW_PATCH}.hash"
python jade_ota.py --log=INFO --skipble --serialport=${JADESERIALPORT} --fwfile=${FW_PATCH}
sleep 2

# finally we test the same exact firmware via ble
FW_PATCH=$(ls ${PATCHDIR}/*_ble_*_ble*_patch.bin)
python jade_ota.py --log=INFO --skipserial --bleidfromserial --serialport=${JADESERIALPORT} --fwfile=${FW_PATCH}
sleep 2

