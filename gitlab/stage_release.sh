#!/bin/bash

# Copy release artifacts into the expected release structure for signing.
# Sign development release artifacts.
# Run by the gitlab release process, called with the branch short SHA and
# (possibly empty) tag name as arguments.

export LABEL=${2:-${1}} # use SHA if tag name not given/empty

# follow 'devfw.sh' convention for staging/upload dirs
export UPLOAD_DIR="release/staging/upload"
export STAGING_DIR="release/staging/$LABEL"

pushd /opt/esp/idf && . ./export.sh && popd

# prod builds
mkdir -p $STAGING_DIR
(cd $STAGING_DIR && mkdir jade jade1.1 jade2.0 jade2.0c jadedev jade1.1dev jade2.0dev jade2.0cdev)
cp -r $STAGING_DIR $UPLOAD_DIR
cp -r build_prod_jade $STAGING_DIR/jade/build_prod
cp -r build_prod_jade_noradio $STAGING_DIR/jade/build_noradio_prod
cp -r build_prod_jade_v1_1 $STAGING_DIR/jade1.1/build_v1_1_prod
cp -r build_prod_jade_v1_1_noradio $STAGING_DIR/jade1.1/build_v1_1_noradio_prod
cp -r build_prod_jade_v2 $STAGING_DIR/jade2.0/build_v2_prod
cp -r build_prod_jade_v2_noradio $STAGING_DIR/jade2.0/build_v2_noradio_prod
cp -r build_prod_jade_v2c $STAGING_DIR/jade2.0c/build_v2c_prod
cp -r build_prod_jade_v2c_noradio $STAGING_DIR/jade2.0c/build_v2c_noradio_prod
# dev builds
cp -r build_dev_jade      build_dev_jade_noradio      $STAGING_DIR/jadedev
cp -r build_dev_jade_v1_1 build_dev_jade_v1_1_noradio $STAGING_DIR/jade1.1dev
cp -r build_dev_jade_v2   build_dev_jade_v2_noradio   $STAGING_DIR/jade2.0dev
cp -r build_dev_jade_v2c  build_dev_jade_v2c_noradio  $STAGING_DIR/jade2.0cdev
# sign dev builds
cd release
./scripts/devfw.sh $LABEL
