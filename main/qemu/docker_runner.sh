#!/usr/bin/env bash
set -e

docker pull blockstream/verde
docker container run -v ${PWD}:/jade blockstream/verde /jade/main/qemu/docker_test.sh
