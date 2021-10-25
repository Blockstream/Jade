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

# then we flash the noblob variant
python ${IDF_PATH}/components/esptool_py/esptool/esptool.py --chip esp32 --port ${JADESERIALPORT} --baud 2000000 --before default_reset --after hard_reset write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect 0xE000 build_noblobs/ota_data_initial.bin 0x1000 build_noblobs/bootloader/bootloader.bin 0x10000 build_noblobs/jade.bin 0x9000 build_noblobs/partition_table/partition-table.bin

source ~/venv3/bin/activate
pip install --require-hashes -r requirements.txt
gcc -O2 -DBSDIFF_EXECUTABLE -o bsdiff build_noblobs/bsdiff.c

sleep 2

# first we test the same exact firmware noblobs via serial
./bsdiff build_noblobs/jade.bin build_noblobs/jade.bin patch.bin
SIZE_TARGET_FILE=$(stat --printf="%s" build_noblobs/jade.bin)
SIZE_PATCH=$(stat --printf="%s" patch.bin)
python -c "import zlib; import sys; open(sys.argv[2], 'wb').write(zlib.compress(open(sys.argv[1], 'rb').read(), 9))" patch.bin patch_${SIZE_TARGET_FILE}_${SIZE_PATCH}.bin
python jade_ota.py --log=INFO --skipble --serialport=${JADESERIALPORT} --fwdeltafile=patch_${SIZE_TARGET_FILE}_${SIZE_PATCH}.bin
rm patch.bin patch_${SIZE_TARGET_FILE}_${SIZE_PATCH}.bin

sleep 2

# now we test from noblob to ble via serial
./bsdiff build_noblobs/jade.bin build/jade.bin patch.bin
SIZE_TARGET_FILE=$(stat --printf="%s" build/jade.bin)
SIZE_PATCH=$(stat --printf="%s" patch.bin)
python -c "import zlib; import sys; open(sys.argv[2], 'wb').write(zlib.compress(open(sys.argv[1], 'rb').read(), 9))" patch.bin patch_${SIZE_TARGET_FILE}_${SIZE_PATCH}.bin
python jade_ota.py --log=INFO --skipble --serialport=${JADESERIALPORT} --fwdeltafile=patch_${SIZE_TARGET_FILE}_${SIZE_PATCH}.bin
rm patch.bin patch_${SIZE_TARGET_FILE}_${SIZE_PATCH}.bin

sleep 2

# now we test the same exact firmware ble via ble
./bsdiff build/jade.bin build/jade.bin patch.bin
SIZE_TARGET_FILE=$(stat --printf="%s" build/jade.bin)
SIZE_PATCH=$(stat --printf="%s" patch.bin)
python -c "import zlib; import sys; open(sys.argv[2], 'wb').write(zlib.compress(open(sys.argv[1], 'rb').read(), 9))" patch.bin patch_${SIZE_TARGET_FILE}_${SIZE_PATCH}.bin
python jade_ota.py --log=INFO --skipserial --serialport=${JADESERIALPORT} --bleidfromserial --fwdeltafile=patch_${SIZE_TARGET_FILE}_${SIZE_PATCH}.bin
rm patch.bin patch_${SIZE_TARGET_FILE}_${SIZE_PATCH}.bin

sleep 2

# now we go back to noblob via ble
./bsdiff build/jade.bin build_noblobs/jade.bin patch.bin
SIZE_TARGET_FILE=$(stat --printf="%s" build_noblobs/jade.bin)
SIZE_PATCH=$(stat --printf="%s" patch.bin)
python -c "import zlib; import sys; open(sys.argv[2], 'wb').write(zlib.compress(open(sys.argv[1], 'rb').read(), 9))" patch.bin patch_${SIZE_TARGET_FILE}_${SIZE_PATCH}.bin
python jade_ota.py --log=INFO --skipserial --serialport=${JADESERIALPORT} --bleidfromserial --fwdeltafile=patch_${SIZE_TARGET_FILE}_${SIZE_PATCH}.bin
rm patch.bin patch_${SIZE_TARGET_FILE}_${SIZE_PATCH}.bin
