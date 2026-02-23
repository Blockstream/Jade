# Dockerfile for building Jade firmware. build with e.g:
# $ docker build -t jade_builder .
#
ARG IDF_INSTALL_TARGETS=esp32,esp32s3
ARG IDF_CLONE_BRANCH_OR_TAG=v5.4.3
ARG IDF_CLONE_SHALLOW=1
# Use the expressif-provided docker which gives us all the tooling plus qemu.
FROM espressif/idf:release-v5.4@sha256:11441b20e4a87dc722ad6d1ef5a920cf8901a62581d8c85a4299a4c0f142e1a3

# These ARGs are easily parseable (eg by HWI)
ARG ESP_IDF_BRANCH=v5.4.3
ARG ESP_IDF_COMMIT=ea1c174c1cbb7348bd8ba0ff1eb306246938dd80

COPY requirements.txt /

# Install libjade/CI dependencies
RUN apt update -yqq
RUN apt install --no-install-recommends --no-install-suggests -yqq clang-format-19 zlib1g-dev

# Don't write Python bytecode, so e.g. mounted local directories don't get
# cache files written by root that they can't easily delete.
ENV PYTHONDONTWRITEBYTECODE=1

# Install our Python dependencies directly into the idf environment,
# to prevent any confusion over which env we are in at any given time.
RUN cd /opt/esp/idf && . ./export.sh && pip install --require-hashes -r /requirements.txt && pip install sphinx

# Allow git operations from docker compose where the jade tree is
# mounted on /host/jade
RUN git config --global --add safe.directory /host/jade
