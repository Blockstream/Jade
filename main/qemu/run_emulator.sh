#!/usr/bin/env bash
set -e

if [ "$#" -gt 1 ] || ([ "$#" -eq 1 ] && [ "$1" != "--larger-display" ]); then
  echo "Error: Invalid parameters."
  exit 1
fi

jade_docker_image=$(grep '^image:' .gitlab-ci.yml | awk '{print $2}')

config_file="sdkconfig_qemu_psram_webdisplay.defaults"
if [ "$1" == "--larger-display" ]; then
  config_file="sdkconfig_qemu_psram_webdisplay_larger.defaults"
fi

# the script makes a copy of the entire repo, cleans the build/config and
# leaves your directory clean

# the reason we copy the repo rather than git clone is to make sure
# we run with your uncommitted changes too

# comment this out to make subsequent builds faster
cmd="cp -r /jade /jade_cpy && cd /jade_cpy"
# uncomment this out to make subsequent builds faster
# cmd="cd /jade"
cmd+=" && cp configs/${config_file} sdkconfig.defaults"
# comment this out to make subsequent builds faster
#cmd+=" && rm -fr build sdkconfig"
cmd+=" && . /root/esp/esp-idf/export.sh && idf.py build"
cmd+=" && ./main/qemu/make-flash-img.sh && ./main/qemu/qemu_run.sh"

docker run --rm -v $PWD:/jade \
  -p 127.0.0.1:30121:30121/tcp -p 127.0.0.1:30122:30122/tcp \
  ${jade_docker_image} /bin/bash -c "${cmd}"
