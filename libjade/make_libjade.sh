#!/bin/bash
#
# Build the Jade firmware into a shared library for in-process debugging
#
# ./libjade/make_libjade.sh [Debug|Release|RelWithDebInfo|MinSizeRel|Sanitize] [--log]
#
set -e

BUILD_TYPE="Debug"
LOG="0"

# iterate through optional arguments and set variables accordingly
for arg in "$@"; do
    case $arg in
        Debug|Release|RelWithDebInfo|MinSizeRel|Sanitize)
            BUILD_TYPE="$arg"
            shift
            ;;
        --log)
            LOG="LOG"
            shift
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: $0 [Debug|Release|RelWithDebInfo|MinSizeRel|Sanitize] [--log]"
            exit 1
            ;;
    esac
done

mkdir -p build_linux
cd build_linux
if [ "${BUILD_TYPE}" == "Sanitize" ]; then
    cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DCMAKE_C_FLAGS"-fsanitize=undefined" -DCMAKE_CXX_FLAGS"-fsanitize=undefined" -DLOG=${LOG} ..
else
    cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DLOG=${LOG} ..
fi
make -j8
cd ..

echo "to use libjade set LD_LIBRARY_PATH=$PWD/build_linux/libjade"
if [ "${BUILD_TYPE}" == "Sanitize" ]; then
    echo "and ASAN_OPTIONS=symbolize=1,detect_leaks=0 LD_PRELOAD=$(ls /usr/lib/gcc/x86_64-linux-gnu/*/libasan.so) UBSAN_OPTIONS=print_stacktrace=1"
fi
