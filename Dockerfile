# Dockerfile for building Jade firmware. build with e.g:
# $ docker build -t jade_builder .
#

# See gitlab/docker.yml to build this image yourself.
FROM blockstream/jade_builder_base@sha256:17574abe64b0915026f324d8df40bf81a60406966b7841e55d3792967d596176

# These ARGs are easily parseable (eg by HWI)
ARG ESP_IDF_BRANCH=v5.5.4
ARG ESP_IDF_COMMIT=735507283d5b2f9fb363a1901172dbd9e847945d

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
