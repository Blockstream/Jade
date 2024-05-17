#!/bin/bash
set -eo pipefail

export gcov_root_path=${PWD}

cd build
mkdir -p  ${gcov_root_path}/build/coverage_report/html
# we can't run idf default gcov target because we need --gcov-ignore-parse-errors and excludes (FIXME: maybe they can be passed in as an argument)

# produce nice html with code coverage
gcovr -r ${gcov_root_path} --gcov-executable xtensa-esp32s3-elf-gcov --exclude "${gcov_root_path}/managed_components" --gcov-ignore-parse-errors -s --html-details ${gcov_root_path}/build/coverage_report/html/index.html

# produce a json file useful to analyze which lines are called the most (FIXME: it would be nice it mentioned functions instead)
gcovr -r ${gcov_root_path} --gcov-executable xtensa-esp32s3-elf-gcov --exclude "${gcov_root_path}/managed_components" --gcov-ignore-parse-errors -s --json -o ${gcov_root_path}/build/coverage_report/coverage.json

${gcov_root_path}/tools/gcov/gcovr_analyzer.py ${gcov_root_path}/build/coverage_report/coverage.json > ${gcov_root_path}/build/coverage_report/analysys.txt

echo "You can open the generated report at ${gcov_root_path}/build/coverage_report/html/index.html"
unset gcov_root_path
