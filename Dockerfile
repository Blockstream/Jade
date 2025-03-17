FROM debian:bookworm-slim@sha256:12c396bd585df7ec21d5679bb6a83d4878bc4415ce926c9e5ea6426d23c60bdc

# These ARGs are easily parseable (eg by HWI)
ARG ESP_IDF_BRANCH=v5.4
ARG ESP_IDF_COMMIT=67c1de1eebe095d554d281952fde63c16ee2dca0

SHELL ["/bin/bash", "-c"]
COPY requirements.txt /

RUN dpkg --add-architecture i386 && apt-get update -qq && apt-get upgrade --no-install-recommends --no-install-suggests -yqq && apt-get install --no-install-recommends --no-install-suggests -yqq git wget libncurses-dev flex bison gperf libffi-dev libssl-dev dfu-util cmake ninja-build build-essential ca-certificates ccache curl make pkg-config python3 python3-dev python3-pip python3-setuptools python3-serial python3-click python3-cryptography python3-future python3-pyparsing python3-pyelftools python3-pkg-resources python3-wheel python3-venv python3-sphinx unzip bluez-tools bluez libusb-1.0-0 clang lld clang-format libglib2.0 libpixman-1-0 libsdl2-2.0-0 libgcrypt20-dev virtualenv libslirp0 gcc-multilib libc6-dev-i386 libsdl2-dev:i386 libcurl4-openssl-dev:i386 libmbedtls-dev:i386 && apt-get -yqq autoremove && apt-get -yqq clean && rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/doc /usr/share/man /usr/share/info /usr/share/locale /usr/share/common-licenses && update-alternatives --install /usr/bin/python python /usr/bin/python3 10 && python3 -m pip install --break-system-packages --user pycodestyle && mkdir ~/esp && cd ~/esp && git clone --quiet --depth=1 --branch ${ESP_IDF_BRANCH} --single-branch --recursive --shallow-submodules https://github.com/espressif/esp-idf.git && cd ~/esp/esp-idf && git checkout ${ESP_IDF_COMMIT} && ./install.sh esp32 esp32s3 && python ~/esp/esp-idf/tools/idf_tools.py install qemu-xtensa && virtualenv -p python3 /venv && source /venv/bin/activate && pip install --require-hashes -r /requirements.txt
