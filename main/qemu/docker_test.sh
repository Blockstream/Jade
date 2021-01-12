#!/usr/bin/env bash
set -e

apt-get update -qq
apt-get install virtualenv -yqq

. /root/esp/esp-idf/export.sh

cd /jade

rm -fr sdkconfig
cp configs/sdkconfig_qemu.defaults sdkconfig.defaults
idf.py all
virtualenv -p python3 /venv3
source /venv3/bin/activate
pip install -r requirements.txt
python ./fwprep.py build/jade.bin build
./main/qemu/make-flash-img.sh
./main/qemu/qemu_ci_flash.sh
