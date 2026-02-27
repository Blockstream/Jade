#!/bin/bash

set -e

BUILD_TYPE="${1:-Debug}"

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
JADE_PATH=$(realpath $SCRIPT_DIR/..)
if [ ! -d "$JADE_PATH" ]; then
    echo "Error: Jade directory not found at $JADE_PATH"
    exit 1
fi

echo "--------------------------------"
echo "Building libjade..."
echo "--------------------------------"
$JADE_PATH/libjade/make_libjade.sh $BUILD_TYPE --log --gui --no-ci
echo "--------------------------------"
echo "Running Jade GUI..."
echo "--------------------------------"
export LD_LIBRARY_PATH=$JADE_PATH/build_linux/libjade:$LD_LIBRARY_PATH
echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo "--------------------------------"
if [ "$BUILD_TYPE" == "Sanitize" ]; then
    export ASAN_OPTIONS=symbolize=1:detect_leaks=0
    echo "ASAN_OPTIONS=$ASAN_OPTIONS"
    echo "--------------------------------"
    export LD_PRELOAD=$(ls /usr/lib/gcc/x86_64-linux-gnu/*/libasan.so | tail -n1)
    echo "LD_PRELOAD=$LD_PRELOAD"
    echo "--------------------------------"
    export UBSAN_OPTIONS=print_stacktrace=1
    echo "UBSAN_OPTIONS=$UBSAN_OPTIONS"
    echo "--------------------------------"
fi
python $JADE_PATH/libjade/gui.py
