FROM debian:bullseye@sha256:08db48d59c0a91afb802ebafc921be3154e200c452e4d0b19634b426b03e0e25
RUN apt-get update -qq && apt-get upgrade --no-install-recommends --no-install-suggests -yqq && apt-get install --no-install-recommends --no-install-suggests -yqq git wget libncurses-dev flex bison gperf libffi-dev libssl-dev dfu-util cmake ninja-build ccache build-essential ca-certificates ccache cmake curl make pkg-config python3 python3-dev python3-pip python3-setuptools python3-serial python3-click python3-cryptography python3-future python3-pyparsing python3-pyelftools python3-pkg-resources python3-wheel unzip bluez-tools bluez libusb-1.0-0 clang-format libglib2.0-dev libpixman-1-dev libgcrypt20-dev virtualenv && apt-get -yqq autoremove && apt-get -yqq clean && rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/*
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 10
RUN python -m pip install --user pycodestyle
RUN export ESP_IDF_COMMIT=2e74914051d14ec2290fc751a8486fb51d73a31e
RUN mkdir ~/esp && cd ~/esp && git clone --quiet --depth=1 --branch v4.3.1 --single-branch --recursive https://github.com/espressif/esp-idf.git
RUN cd ~/esp/esp-idf && git checkout ${ESP_IDF_COMMIT} && ./install.sh
RUN export ESP_QEMU_COMMIT=fd85235d17cd8813d6a31f5ced3c5acbf1933718
RUN git clone --quiet --depth 1 --branch esp-develop-20210826 --single-branch --recursive https://github.com/espressif/qemu.git \
&& (cd qemu && git checkout ${ESP_QEMU_COMMIT} && ./configure --target-list=xtensa-softmmu \
    --enable-gcrypt \
    --enable-debug --enable-sanitizers \
    --disable-strip --disable-user \
    --disable-capstone --disable-vnc \
    --disable-sdl --disable-gtk && ninja -C build)
