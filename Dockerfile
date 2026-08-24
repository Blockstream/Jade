# Dockerfile for building Jade firmware. build with e.g:
# $ docker build -t jade_builder .
#

# See gitlab/docker.yml to build this image yourself.
FROM blockstream/jade_builder_base@sha256:c6ae8bea021bce54f8e0ef09b87c4294182eb9a0faf02bc536af035492c47db6

# These ARGs are easily parseable (eg by HWI)
ARG ESP_IDF_BRANCH=v5.5.5
ARG ESP_IDF_COMMIT=b774170ff46c393eeb5e495ea37936038d3f4f4f

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
