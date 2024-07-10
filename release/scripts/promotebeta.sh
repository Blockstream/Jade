#!/bin/bash

HWDIRS="jade jade1.1 jade2.0 jadedev jade1.1dev jade2.0dev"

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
