#!/bin/bash
set -eo pipefail

# this is the minimum to run qemu
# xtensa-softmmu/qemu-system-xtensa -nographic \
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

(cd /qemu && xtensa-softmmu/qemu-system-xtensa -nographic \
    -machine esp32 \
    -drive file=flash_image.bin,if=mtd,format=raw \
    -global driver=timer.esp32.timg,property=wdt_disable,value=true \
    -nic user,model=open_eth,id=lo0,hostfwd=tcp:0.0.0.0:2222-:2222 \
    -serial pty &)
sleep 4

# TODO: put virtualenv in the docker-image, and the virtualenv in the runner homedir
apt-get update -qq && apt-get install virtualenv -yqq
virtualenv -p python3 venv3

source venv3/bin/activate
pip install --require-hashes -r requirements.txt -r pinserver/requirements.txt

python jade_ota.py --log=INFO --skipble --serialport=tcp:localhost:2222

python test_jade.py --log=INFO --skipble --qemu --serialport=tcp:localhost:2222
