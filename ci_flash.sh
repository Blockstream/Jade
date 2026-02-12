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

# NOTE: tools/fwprep.py should have run in the build step and produced the compressed firmware file
FW_FULL=$(ls build/*_fw.bin)
python jade_ota.py --push-mnemonic --log=INFO --serialport=${JADESERIALPORT} --fwfile=${FW_FULL} ${SKIP_ARGS}

sleep 5
python -c "from jadepy import JadeAPI; jade = JadeAPI.create_serial(device=\"${JADESERIALPORT}\", timeout=5) ; jade.connect(); jade.drain(); jade.disconnect()"

python test_jade.py --log=INFO --serialport=${JADESERIALPORT} ${SKIP_ARGS}

if [ ! -f /.dockerenv ]; then
    deactivate
fi
