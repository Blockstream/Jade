#! /usr/bin/env bash

# Helper to generate coverage reports.
# ./tools/coverage.sh clean : Sets coverage stats to 0.
# ./tools/coverage.sh       : Calculates coverage stats, produces
#                             build_linux/lcov/index.html as output.
lcov="lcov --directory=build_linux/ --base-directory build_linux/ --gcov-tool gcov"

if [ "$1" = "clean" ]; then
    $lcov --ignore-errors empty --zerocounters
    $lcov --ignore-errors empty --output-file build_linux/lcov_base --capture --initial
else
    $lcov --output-file build_linux/lcov_result --capture --ignore-errors=gcov
    $lcov --output-file build_linux/lcov_total --add-tracefile build_linux/lcov_base --add-tracefile build_linux/lcov_result --ignore-errors=gcov
    genhtml --demangle-cpp -o build_linux/lcov/ build_linux/lcov_total
fi
