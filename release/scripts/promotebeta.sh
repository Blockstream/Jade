#!/bin/bash

HWDIRS="jade jade1.1 jadedev jade1.1dev"

STAGING="staging"
UPLOAD="upload"
WORKING_DIR="${STAGING}/${UPLOAD}"

pushd "${WORKING_DIR}"
for hwdir in ${HWDIRS}
do
  pushd "${hwdir}"
  cat LATEST PREVIOUS > PREVIOUS.tmp
  mv PREVIOUS.tmp PREVIOUS
  cp BETA LATEST
  popd
done
popd
