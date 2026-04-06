#!/usr/bin/env bash
set -e

function usage {
    if [ -n "$1" ]; then
        echo "error: $1" >&2
    fi
    echo "Usage: ${0} [OPTIONS]"
    echo "OPTIONS:"
    echo "    --larger-display    Use a larger QEMU web display"
    echo "    -h | --help         Show this help message"
    if [ -n "$1" ]; then
        exit 1
    fi
    exit 0
}

LARGER_DISPLAY=""

while true; do
    case "$1" in
        --larger-display) LARGER_DISPLAY=1; shift ;;
        -h | --help) usage ;;
        "") break ;;
        *) usage "unknown option $1" ;;
    esac
done

jade_docker_image=$(grep '^image:' .gitlab-ci.yml | awk '{print $2}')

config_file="sdkconfig_qemu.defaults"
QEMU_CONFIG_ARGS="--dev --psram --webdisplay"
if [ -n "$LARGER_DISPLAY" ]; then
    QEMU_CONFIG_ARGS="$QEMU_CONFIG_ARGS --webdisplay-larger"
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
cmd+=" && pushd /opt/esp/idf && . ./export.sh && popd"
cmd+=" && ./tools/switch_to.sh qemu ${QEMU_CONFIG_ARGS}"
cmd+=" && idf.py build"
cmd+=" && ./main/qemu/make_flash_img.sh && ./main/qemu/qemu_run.sh"

docker run --rm -v $PWD:/jade \
  -p 127.0.0.1:30121:30121/tcp -p 127.0.0.1:30122:30122/tcp \
  ${jade_docker_image} /bin/bash -c "${cmd}"
