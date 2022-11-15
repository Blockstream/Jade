FROM debian:bullseye@sha256:bfe6615d017d1eebe19f349669de58cda36c668ef916e618be78071513c690e5 as base
RUN apt-get update -qq && apt-get upgrade --no-install-recommends --no-install-suggests -yqq && apt-get install --no-install-recommends --no-install-suggests -yqq git wget libncurses-dev flex bison gperf libffi-dev libssl-dev dfu-util cmake ninja-build ccache build-essential ca-certificates ccache cmake curl make pkg-config python3 python3-dev python3-pip python3-setuptools python3-serial python3-click python3-cryptography python3-future python3-pyparsing python3-pyelftools python3-pkg-resources python3-wheel unzip bluez-tools bluez libusb-1.0-0 clang-format libglib2.0-dev libpixman-1-dev libgcrypt20-dev virtualenv && apt-get -yqq autoremove && apt-get -yqq clean && rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/*
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 10
RUN python -m pip install --user pycodestyle

FROM base AS esp-idf

# These ARGs are easily parseable (eg by HWI)
ARG ESP_IDF_BRANCH=v4.4.3
ARG ESP_IDF_COMMIT=6407ecb3f8d2cc07c4c230e7e64f2046af5c86f7
RUN mkdir ~/esp && cd ~/esp && git clone --quiet --depth=1 --branch ${ESP_IDF_BRANCH} --single-branch --recursive https://github.com/espressif/esp-idf.git
RUN cd ~/esp/esp-idf && git checkout ${ESP_IDF_COMMIT} && ./install.sh esp32

FROM base AS esp-qemu

# These ARGs are easily parseable (eg by HWI)
ARG ESP_QEMU_BRANCH=esp-develop-20220802
ARG ESP_QEMU_COMMIT=686dadc4c50f5194b4edfb9a996c3527d5f67efc
RUN git clone --quiet --depth 1 --branch ${ESP_QEMU_BRANCH} --single-branch --recursive https://github.com/espressif/qemu.git \
&& cd qemu && git checkout ${ESP_QEMU_COMMIT} \
    && ./configure --target-list=xtensa-softmmu --static --prefix=/opt \
    --enable-lto \
    --enable-gcrypt \
    --enable-sanitizers \
    --disable-user \
    --disable-opengl \
    --disable-curses \
    --disable-capstone \
    --disable-vnc \
    --disable-parallels \
    --disable-qed \
    --disable-vvfat \
    --disable-vdi \
    --disable-qcow1 \
    --disable-dmg \
    --disable-cloop \
    --disable-bochs \
    --disable-replication \
    --disable-live-block-migration \
    --disable-keyring \
    --disable-containers \
    --disable-docs \
    --disable-libssh \
    --disable-xen \
    --disable-tools \
    --disable-zlib-test \
    --disable-sdl \
    --disable-gtk \
    --disable-vhost-scsi \
    --disable-qom-cast-debug \
    --disable-tpm \
    && ninja -C build install && rm -fr /qemu

FROM esp-idf
COPY --from=esp-qemu /opt /opt
COPY requirements.txt /
COPY pinserver/requirements.txt /ps_requirements.txt
SHELL ["/bin/bash", "-c"]
RUN virtualenv -p python3 /venv && source /venv/bin/activate && pip install --require-hashes -r /requirements.txt -r /ps_requirements.txt
