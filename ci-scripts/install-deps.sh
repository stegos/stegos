#!/usr/bin/env bash

install_deps_linux() {
  apt-get update && \
    apt-get install -y build-essential \
        binutils-dev \
        clang \
        cmake \
        curl \
        libcurl4-openssl-dev \
        libdw-dev \
        libiberty-dev \
        libssl-dev \
        protobuf-compiler \
        pkg-config \
        wget \
        zlib1g-dev

  (cd /usr/local && curl -L https://github.com/emotiq/emotiq-external-libs/releases/download/release-0.1.15/emotiq-external-libs-linux.tgz \
    | tar xvfz -)
  ldconfig
}

install_deps_macos() {
  brew install gmp pbc protobuf zlib cmake pkg-config
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
