#!/bin/bash
#
# Build the Jade firmware into a shared library for in-process debugging
#
# ./libjade/make_libjade.sh [Debug|Release|RelWithDebInfo|MinSizeRel|Sanitize]
#
set -e

BUILD_TYPE="${1:-Debug}"

rm -rf build_linux
mkdir build_linux
cd build_linux
if [ "${BUILD_TYPE}" == "Sanitize" ]; then
    cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DCMAKE_C_FLAGS"-fsanitize=undefined" -DCMAKE_CXX_FLAGS"-fsanitize=undefined" ..
else
    cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ..
fi
make -j8

echo "to use libjade set LD_LIBRARY_PATH=$PWD/build_linux/libjade"
if [ "${BUILD_TYPE}" == "Sanitize" ]; then
    echo "and ASAN_OPTIONS=symbolize=1,detect_leaks=0 LD_PRELOAD=$(ls /usr/lib/gcc/x86_64-linux-gnu/*/libasan.so) UBSAN_OPTIONS=print_stacktrace=1"
fi
