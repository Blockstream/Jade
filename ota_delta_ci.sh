#!/usr/bin/env bash
set -eo pipefail

if [[ -z ${JADESERIALPORT} ]]; then
    echo "JADESERIALPORT not set, defaulting..."
    if [ "$(uname)" == "Darwin" ]; then
        JADESERIALPORT=/dev/cu.SLAB_USBtoUART
    elif [ -c /dev/ttyUSB0 ]; then
        JADESERIALPORT=/dev/ttyUSB0
    else
        JADESERIALPORT=/dev/ttyACM0
    fi
fi
echo "Using JADESERIALPORT ${JADESERIALPORT}"

TARGET_CHIP=${1}
SKIP_ARGS=${2}

if [ -z "$IDF_PATH" ]; then
    get_idf
fi

./tools/initial_flash_${TARGET_CHIP}.sh ${JADESERIALPORT}
sleep 1

if [ -f /.dockerenv ]; then
    # Running under docker/the CI: main requirements are
    # already installed into the idf environment.
    # Just install the pinserver requirements
    pip install -r pinserver/requirements.txt
else
    # Running locally: set up a virtualenv
    virtualenv -p python3 venv3
    source venv3/bin/activate
    pip install --require-hashes -r requirements.txt
    pip install -r pinserver/requirements.txt
fi

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
# into the patches/ dir.
mkdir -p patches

function cleanup {
    local ret=$?
    rm -rf ./tools/bsdiff patches
    exit $ret
}
trap cleanup EXIT

./tools/mkpatch.py ${FW_NORADIO} ${FW_NORADIO} patches --force
./tools/mkpatch.py ${FW_BLE} ${FW_BLE} patches --force
./tools/mkpatch.py ${FW_NORADIO} ${FW_BLE} patches --force  # makes both directions
rm -f ./tools/bsdiff
sleep 2

# first we ota to noradio via ble (or serial if skipping ble)
# NOTE: the filename is of the pattern: 'final-from-base' - hence noradio*ble*patch.bin
FW_PATCH=$(ls patches/*_noradio_*_ble*_patch.bin)
cp "${FW_NORADIO}.hash" "${FW_PATCH}.hash"
python jade_ota.py --log=INFO ${SKIP_SERIAL} ${SKIP_ARGS} --serialport=${JADESERIALPORT} --fwfile=${FW_PATCH}

# then we test the same exact firmware via serial
FW_PATCH=$(ls patches/*_noradio_*_noradio*_patch.bin)
python jade_ota.py --log=INFO --skipble --serialport=${JADESERIALPORT} --fwfile=${FW_PATCH}
sleep 2

# then we test from noradio to ble via serial
# NOTE: the filename is of the pattern: 'final-from-base' - hence ble*noradio*patch.bin
FW_PATCH=$(ls patches/*_ble_*_noradio*_patch.bin)
cp "${FW_BLE}.hash" "${FW_PATCH}.hash"
python jade_ota.py --log=INFO --skipble --serialport=${JADESERIALPORT} --fwfile=${FW_PATCH}
sleep 2

# finally we test the same exact firmware via ble (or serial if skipping ble)
FW_PATCH=$(ls patches/*_ble_*_ble*_patch.bin)
python jade_ota.py --log=INFO ${SKIP_SERIAL} ${SKIP_ARGS} --serialport=${JADESERIALPORT} --fwfile=${FW_PATCH}
sleep 2
