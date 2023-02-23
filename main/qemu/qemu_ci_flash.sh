#!/bin/bash
set -eo pipefail

# this is the minimum to run qemu
# build/qemu-system-xtensa -nographic \
#     -machine esp32 \
#     -drive file=flash_image.bin,if=mtd,format=raw

# if you want to add efuses first you create with dd the file then pass it to qemu
# we ignore efuses for debug
# dd if=/dev/zero bs=1 count=124 of=qemu_efuse.bin
# -drive file=qemu_efuse.bin,if=none,format=raw,id=efuse \
# -global driver=nvram.esp32.efuse,property=drive,value=efuse \

# if you want to expose the serial via tcp/pty/console respectively
# -serial tcp::5555,server,nowait)
# -serial pty)
# -serial mon:stdio)


# if you want to put qemu in a state where it can be used with idf.py flash or esptool.py
# -global driver=esp32.gpio,property=strap_mode,value=0x0f \

/opt/bin/qemu-system-xtensa -nographic \
    -machine esp32 \
    -m 4M \
    -drive file=/flash_image.bin,if=mtd,format=raw \
    -nic user,model=open_eth,id=lo0,hostfwd=tcp:0.0.0.0:30121-:30121 \
    -drive file=/qemu_efuse.bin,if=none,format=raw,id=efuse \
    -global driver=nvram.esp32.efuse,property=drive,value=efuse \
    -serial pty &
sleep 4

source /venv/bin/activate
pip install --require-hashes -r requirements.txt -r pinserver/requirements.txt

# Build the bsdiff tool in the 'tools' directory (source file in the build dir)
gcc -O2 -DBSDIFF_EXECUTABLE -o ./tools/bsdiff components/esp32_bsdiff/bsdiff.c

# OTA the build firmware
# NOTE: tools/fwprep.py should have run in the build step and produced the compressed firmware file
FW_FULL=$(ls build/*_fw.bin)
python jade_ota.py --log=INFO --skipble --serialport=tcp:localhost:30121 --fwfile=${FW_FULL}

# Flash a simple patch-to-self, just to smoke test ota-delta
./tools/mkpatch.py ${FW_FULL} ${FW_FULL} build/
FW_PATCH=$(ls ./build/*_patch.bin)
cp "${FW_FULL}.hash" "${FW_PATCH}.hash"
python jade_ota.py --log=INFO --skipble --serialport=tcp:localhost:30121 --fwfile=${FW_PATCH}

# Run the tests - long timeout for bcur-fragment iteration test in 'run_remote_selfcheck()/selfcheck.c'
python test_jade.py --log=INFO --skipble --qemu --serialport=tcp:localhost:30121 --serialtimeout=300
