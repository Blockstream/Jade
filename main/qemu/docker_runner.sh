#!/usr/bin/env bash
set -e

docker pull blockstream/verde
docker run -v ${PWD}:/jade blockstream/verde -p 2222:2222 /jade/main/qemu/docker_test.sh
