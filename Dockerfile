FROM debian:bullseye@sha256:2906804d2a64e8a13a434a1a127fe3f6a28bf7cf3696be4223b06276f32f1f2d
RUN apt-get update -qq && apt-get upgrade --no-install-recommends --no-install-suggests -yqq && apt-get install --no-install-recommends --no-install-suggests -yqq git wget libncurses-dev flex bison gperf libffi-dev libssl-dev dfu-util cmake ninja-build ccache build-essential ca-certificates ccache cmake curl make pkg-config python3 python3-dev python3-pip python3-setuptools python3-serial python3-click python3-cryptography python3-future python3-pyparsing python3-pyelftools python3-pkg-resources python3-wheel unzip bluez-tools bluez libusb-1.0-0 clang-format libglib2.0-dev libpixman-1-dev libgcrypt20-dev virtualenv && apt-get -yqq autoremove && apt-get -yqq clean && rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/*
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 10
RUN python -m pip install --user pycodestyle

# These ARGs are easily parseable (eg by HWI)
ARG ESP_IDF_BRANCH=v4.3.2
ARG ESP_IDF_COMMIT=8bf14a9238329954c7c5062eeeda569529aedf75
RUN mkdir ~/esp && cd ~/esp && git clone --quiet --depth=1 --branch ${ESP_IDF_BRANCH} --single-branch --recursive https://github.com/espressif/esp-idf.git
RUN cd ~/esp/esp-idf && git checkout ${ESP_IDF_COMMIT} && ./install.sh esp32

# These ARGs are easily parseable (eg by HWI)
ARG ESP_QEMU_BRANCH=esp-develop-20210826
ARG ESP_QEMU_COMMIT=fd85235d17cd8813d6a31f5ced3c5acbf1933718
RUN git clone --quiet --depth 1 --branch ${ESP_QEMU_BRANCH} --single-branch --recursive https://github.com/espressif/qemu.git \
&& (cd qemu && git checkout ${ESP_QEMU_COMMIT} && ./configure --target-list=xtensa-softmmu \
    --enable-gcrypt \
    --enable-debug --enable-sanitizers \
    --disable-strip --disable-user \
    --disable-capstone --disable-vnc \
    --disable-sdl --disable-gtk && ninja -C build)
