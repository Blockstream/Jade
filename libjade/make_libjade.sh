#!/bin/bash
#
# Build the Jade firmware into a shared library for in-process debugging
#
# ./libjade/make_libjade.sh [Debug|Release|RelWithDebInfo|MinSizeRel|Sanitize] [--log] [--camera] [--no-ci] [--coverage]
#
set -e

BUILD_TYPE="Debug"
LOG="0"
CI="CI"
CAMERA="0"

usage() {
    echo "Usage: $0 [Debug|Release|RelWithDebInfo|MinSizeRel|Sanitize] [--log] [--camera] [--no-ci] [--coverage]"
    exit 1
}

# iterate through optional arguments and set variables accordingly
for arg in "$@"; do
    case $arg in
        --help)
            usage
            ;;
        Debug|Release|RelWithDebInfo|MinSizeRel|Sanitize)
            BUILD_TYPE="$arg"
            shift
            ;;
        --coverage)
            COVERAGE="COVERAGE"
            shift
            ;;
        --log)
            LOG="LOG"
            shift
            ;;
        --no-ci)
            CI="0"
            shift
            ;;
        --camera)
            CAMERA="CAMERA"
            shift
            ;;
        *)
            echo "Unknown argument: $arg"
            usage
            ;;
    esac
done

mkdir -p build_linux
cd build_linux
EXTRA_ARGS=''
if [ "${BUILD_TYPE}" == "Sanitize" ]; then
    EXTRA_ARGS='-DCMAKE_C_FLAGS"-fsanitize=undefined" -DCMAKE_CXX_FLAGS"-fsanitize=undefined"'
fi
cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${EXTRA_ARGS} -DLOG=${LOG} -DCOVERAGE=${COVERAGE} -DCAMERA=${CAMERA} -DCI=${CI} ..
make -j8
cd ..

echo "to use libjade set LD_LIBRARY_PATH=$PWD/build_linux/libjade"
if [ "${BUILD_TYPE}" == "Sanitize" ]; then
    echo "and ASAN_OPTIONS=symbolize=1,detect_leaks=0 LD_PRELOAD=$(ls /usr/lib/gcc/x86_64-linux-gnu/*/libasan.so) UBSAN_OPTIONS=print_stacktrace=1"
fi
