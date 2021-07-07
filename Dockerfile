FROM debian:buster@sha256:33a8231b1ec668c044b583971eea94fff37151de3a1d5a3737b08665300c8a0b
RUN apt-get update -qq && apt-get upgrade --no-install-recommends --no-install-suggests -yqq && apt-get install --no-install-recommends --no-install-suggests -yqq git wget libncurses-dev flex bison gperf libffi-dev libssl-dev dfu-util cmake ninja-build ccache build-essential ca-certificates ccache cmake curl make pkg-config python3 python3-pip python3-setuptools python3-serial python3-click python3-cryptography python3-future python3-pyparsing python3-pyelftools python3-pkg-resources python3-wheel unzip bluez-tools bluez libusb-1.0-0 clang-format libglib2.0-dev libpixman-1-dev && apt-get -yqq autoremove && apt-get -yqq clean && rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/*
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 10
RUN python -m pip install --user pycodestyle
RUN export ESP_IDF_COMMIT=c40f2590bf759ff60ef122afa79b4ec04e7633d2
RUN mkdir ~/esp && cd ~/esp && git clone --depth=1 --branch v4.2 --single-branch --recursive https://github.com/espressif/esp-idf.git
RUN cd ~/esp/esp-idf && git checkout ${ESP_IDF_COMMIT} && ./install.sh
RUN git clone --quiet --depth 1 --single-branch --branch esp-develop git://github.com/espressif/qemu \
&& (cd qemu && ./configure --target-list=xtensa-softmmu \
    --enable-debug --enable-sanitizers \
    --disable-strip --disable-user \
    --disable-capstone --disable-vnc \
    --disable-sdl --disable-gtk && make -j$(grep ^processor /proc/cpuinfo | wc -l))
