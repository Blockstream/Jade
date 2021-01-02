#!/bin/bash
set -eo pipefail

firmwares=$(ls -1a *_fw.bin > LATEST)

sha256sum * | gpg --clearsign > SHA256SUMS.asc
cat LATEST
cat SHA256SUMS.asc
