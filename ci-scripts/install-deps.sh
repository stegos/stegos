#!/usr/bin/env bash

install_deps_linux() {
    apt-get update &&
        apt-get install -y build-essential \
            binutils-dev \
            clang \
            cmake \
            curl \
            libcurl4-openssl-dev \
            libdw-dev \
            libgmp-dev \
            libiberty-dev \
            libssl-dev \
            pkg-config \
            wget \
            zlib1g-dev

    (cd /usr/local && curl -L https://github.com/stegos/stegos-external-libs/releases/download/v0.5/stegos-external-libs-linux.tgz |
        tar xvfz -)
    ldconfig
}

install_deps_macos() {
    brew install gmp mpfr protobuf zlib cmake pkg-config
    (cd /usr/local && curl -L https://github.com/stegos/stegos-external-libs/releases/download/v0.5/stegos-external-libs-osx.tgz |
        tar xvfz -)
}

case $(uname -s) in
Linux*)
    install_deps_linux
    ;;
Darwin*)
    install_deps_macos
    ;;
*)
    echo Unknown OS \"$(uname -s)\". Terminating...
    exit 127
    ;;
esac
