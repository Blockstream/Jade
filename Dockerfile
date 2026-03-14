# Dockerfile for building Jade firmware. build with e.g:
# $ docker build -t jade_builder .
#

# FIXME: The idf built 5.4.3 docker images generates bad firmware images for 1.x
#        devices. Building this image ourselves (see gitlab/docker.yml) works,
#        so use our image instead until upstream is fixed.
#ARG IDF_INSTALL_TARGETS=esp32,esp32s3
#ARG IDF_CLONE_BRANCH_OR_TAG=v5.4.3
#ARG IDF_CLONE_SHALLOW=1
## Use the expressif-provided docker which gives us all the tooling plus qemu.
#FROM espressif/idf:release-v5.4@sha256:11441b20e4a87dc722ad6d1ef5a920cf8901a62581d8c85a4299a4c0f142e1a3

# See gitlab/docker.yml to build this image yourself.
FROM blockstream/jade_builder_base@sha256:6f64874834696a7af1f77019ab2aee400d351146bc0de8bbfc9f5b30bf8f7cf9

# These ARGs are easily parseable (eg by HWI)
ARG ESP_IDF_BRANCH=v5.4
ARG ESP_IDF_COMMIT=67c1de1eebe095d554d281952fde63c16ee2dca0

COPY requirements.txt /

# Install libjade/CI dependencies
RUN apt update -yqq
RUN apt install --no-install-recommends --no-install-suggests -yqq g++ clang-format-19 zlib1g-dev

# Don't write Python bytecode, so e.g. mounted local directories don't get
# cache files written by root that they can't easily delete.
ENV PYTHONDONTWRITEBYTECODE=1

# Install our Python dependencies directly into the idf environment,
# to prevent any confusion over which env we are in at any given time.
RUN cd /opt/esp/idf && . ./export.sh && pip install --require-hashes -r /requirements.txt && pip install sphinx

# Allow git operations from docker compose where the jade tree is
# mounted on /host/jade
RUN git config --global --add safe.directory /host/jade
