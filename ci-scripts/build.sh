#!/bin/bash
#
# CI tool
#

if test $(id -u) -eq 0; then
    sudo() {
        $@
    }
    # don't call sudo under root for slim docker images
fi

RUST_TOOLCHAIN=${RUST_TOOLCHAIN:-$(cat rust-toolchain)}
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-./target}
mkdir -p ${CARGO_TARGET_DIR}

if [[ -z "${NUMCPUS}" ]]; then
  echo "NUMCPUS was not set, so setting number of jobs to count of cpus cores."
  export NUMCPUS=$(grep -c '^processor' /proc/cpuinfo)
fi
gmp_vers=6.1.2
mpfr_vers=4.0.2
flint_vers=2.5.2
rocksdb_ver=6.2.2


configure_mingw() {
    echo "Found Win-GNU, setting tar to local, and sudo to nothing"
    shopt -s expand_aliases
    alias tar=/usr/bin/tar

    #don't call sudo and ldconfig under mingw
    sudo()
    {
        $@
    }
    ldconfig() {
        $@
    }

    export PATH=/mingw64/bin:$PATH
    export HOME=`cygpath -u $USERPROFILE`
    export RUSTUP_TOOLCHAIN=$RUST_TOOLCHAIN-x86_64-pc-windows-gnu
    export CPATH=/usr/local/include:/mingw64/include/flint:/mingw64/include/
    export FLINT_LIB_DIR=/mingw64/lib
    export SNAPPY_LIB_DIR=/mingw64/lib
    export ZSTD_LIB_DIR=/mingw64/lib
    export LZ4_LIB_DIR=/mingw64/lib
    export ROCKSDB_LIB_DIR=/mingw64/lib
    export ROCKSDB_STATIC
    export SNAPPY_STATIC
    export ZSTD_STATIC
    export LZ4_STATIC
}

# Install dependencies on Linux via apt
install_packages_linux() {
    if test -f /var/tmp/.stegos_deps_installed; then
        return 0
    fi
    if test -f /etc/debian_version; then
        echo "Installing dependencies using apt..."
        export DEBIAN_FRONTEND=noninteractive
        sudo apt-get update && \
        sudo apt-get install -y \
            binutils-dev \
            build-essential \
            clang \
            curl \
            git \
            gzip \
            libgmp-dev \
            libiberty-dev \
            libmpfr-dev \
            libssl-dev \
            pkg-config \
            tar \
            zip \
            zlib1g-dev
    elif test -f /etc/redhat-release; then
        sudo yum install -y\
            binutils-devel \
            clang \
            curl \
            gcc \
            gcc-c++ \
            git \
            gmp-devel \
            gmp-static \
            gzip \
            kernel-devel \
            make \
            mpfr-devel \
            openssl-devel \
            pkg-config \
            tar \
            zip \
            zlib-devel
    else
        2>&1 echo "Unsupported Linux distro"
        exit 1
    fi
    touch /var/tmp/.stegos_deps_installed
}

# Install dependencies on macOS via brew
install_packages_macos() {
    echo "Installing dependencies using brew..."
    for formula in gmp mpfr protobuf zlib cmake pkg-config; do
        if ! brew ls --versions $formula >/dev/null; then
            brew install $formula
        fi
    done
}

install_packages_mingw() {
    LLVM_VERSION=5.0.0-1
    MINGW_URL=http://repo.msys2.org/mingw/x86_64/mingw-w64-x86_64
    PEXT=any.pkg.tar.xz
    URL_VER=$LLVM_VERSION-$PEXT

    # mingw-gcc set _mingw_ target during compile, while msys-gcc set to gnuc.
    # And some libraryes didn't understands OS.
    # Thats why install gcc set from mingw repos.
    # Also install building dependencies for rocksdb.

    pacman -S --noconfirm --needed mingw-w64-x86_64-gflags \
      mingw-w64-x86_64-zlib \
      mingw-w64-x86_64-zstd \
      mingw-w64-x86_64-lz4 \
      mingw-w64-x86_64-snappy \
      mingw-w64-x86_64-gmp \
      mingw-w64-x86_64-mpfr \
      mingw-w64-x86_64-gcc  \
      mingw-w64-x86_64-cmake  \
      m4 make diffutils curl patch tar

    #downgrade clang to specific versions for bindgen
    pacman -U --noconfirm $MINGW_URL-clang-$URL_VER $MINGW_URL-llvm-$URL_VER
}

# Install Rust toolchain via rustup
install_toolchain() {
    if ! rustup show | grep -q ${RUST_TOOLCHAIN}; then
        echo "Installing Rust ${RUST_TOOLCHAIN}"
        curl -L https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_TOOLCHAIN}

        #if env script is found, execute, if not add bin to path
        if [ -f $HOME/.cargo/env ]
        then
          source $HOME/.cargo/bin
        else
          export PATH=$HOME/.cargo/bin:$PATH
        fi
        rustup show
        rustc --version
    fi

    if ! rustfmt --version >/dev/null; then
        echo "Installing rustfmt"
        rustup component add rustfmt
    fi

    if uname -s | grep -q Linux && ! cargo audit --version | grep -q Audit; then
        echo "Installing cargo-audit"
        cargo install cargo-audit
    fi

    if uname -s | grep -q Linux && ! grcov --version >/dev/null; then
        echo "Installing grcov"
        cargo install grcov
    fi
}

install_gmp_linux() {
    if test -f /usr/local/lib/libgmp.a || \
        test -f /usr/lib64/libgmp.a || \
        test -f /usr/lib/x86_64-linux-gnu/libgmp.a; then
         return 0
    fi
    # install gmp
    echo "Building libgmp..."
    curl -L https://gmplib.org/download/gmp/gmp-${gmp_vers}.tar.xz | /usr/bin/tar xvfJ - &&
    cd gmp-${gmp_vers} &&
    CFLAGS="-O3 -g -fexceptions -funwind-tables -fno-omit-frame-pointer -fPIC" \
    ./configure --prefix=/usr/local \
     --enable-static \
     --disable-shared &&
    make -j $NUMCPUS &&
    sudo make install &&
    cd .. &&
    rm -r gmp-${gmp_vers}
    sudo ldconfig
}

# Build dependencies on Linux
install_mpfr_linux() {
    if test -f /usr/local/lib/libmpfr.a ||
      test -f /usr/lib64/libmpfr.a ||
      test -f /usr/lib/x86_64-linux-gnu/libmpfr.a; then
       return 0
    fi

    echo "Building libmpfr..."
    curl -L https://www.mpfr.org/mpfr-current/mpfr-${mpfr_vers}.tar.gz | tar xvzf - && \
    cd mpfr-${mpfr_vers} && \
    CFLAGS="-O3 -g -fexceptions -funwind-tables -fno-omit-frame-pointer -fPIC" \
    ./configure \
       --prefix=/usr/local \
       --with-gmp=/usr/local \
       --enable-static \
       --disable-shared \
    && \
    make -j 8 && \
    sudo make install && \
    cd .. && \
    rm -rf mpfr-${mpfr_vers}
    sudo ldconfig
}

install_flint_linux() {
    if test -f /usr/local/lib/libflint.a; then
        return 0
    fi
    echo "Building libflint..."
    curl -L http://www.flintlib.org/flint-${flint_vers}.tar.gz | tar xvzf - && \
    cd flint-${flint_vers} && \
    CFLAGS="-O3 -g -fexceptions -funwind-tables -fno-omit-frame-pointer -fPIC" \
    ./configure \
       --prefix=/usr/local \
       --with-gmp=/usr/local \
       --with-mpfr=/usr/local \
       --enable-static \
       --disable-shared \
       --enable-tls \
       --enable-cxx && \
    make -j $NUMCPUS
    sudo make install && \
    cd .. && \
    rm -rf flint-${flint_vers}
    sudo ldconfig
}


install_flint_mingw() {
    if test -f /mingw64/lib/libflint.a; then
       return 0
    fi
    echo "Building libflint..."
    curl -L http://www.flintlib.org/flint-${flint_vers}.tar.gz | tar xvzf - && \
    cd flint-${flint_vers} && \
    CFLAGS="-O3 -g -fexceptions -funwind-tables -fno-omit-frame-pointer -fPIC" \
    ./configure \
        --prefix=/mingw64 \
        --with-gmp=/mingw64 \
        --with-mpfr=/mingw64 \
        --enable-static \
        --disable-shared \
        --enable-tls \
        --enable-cxx && \
    make -j $NUMCPUS
    sudo make install && \
    cd .. && \
    rm -rf flint-${flint_vers}
    sudo ldconfig
}


install_rocksdb_mingw() {
    if test -f /mingw64/lib/librocksdb.a ; then
          return 0
    fi
    # install librocksdb
    echo "Building librocksdb..."
    curl -L https://github.com/facebook/rocksdb/archive/v${rocksdb_ver}.tar.gz  | tar xvzf -

    echo "Patching rocksdb..."
    cd rocksdb-${rocksdb_ver}
    patch ./CMakeLists.txt ../ci-scripts/win/rocksdb_cmake.patch
    patch ./port/win/port_win.h ../ci-scripts/win/rocksdb_localtime_mingw.patch

    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib \
          -DWITH_ZSTD=ON -DWITH_SNAPPY=ON -DWITH_SNAPPY=ON \
          -DWITH_GFLAGS=OFF -DWITH_WINDOWS_UTF8_FILENAMES=ON -DPORTABLE=ON \
          -DUSE_RTTI=ON -DWITH_TESTS=OFF -DFAIL_ON_WARNINGS=OFF \
          -DSNAPPY_LIBRARIES="/mingw64/lib/libsnappy.a" \
          -DZSTD_LIBRARIES="/mingw64/lib/libzstd.a" \
          -G "MSYS Makefiles" \
          -S . -B build &&
    cmake --build build --target rocksdb-shared -- -j $NUMCPUS &&
    # cmake --build build --target install
    # install script broken for mingw, so just copy
    mkdir -p /mingw64/lib/
    mv ./build/librocksdb-shared.dll.a /mingw64/lib/librocksdb.a &&
    mv ./build/librocksdb-shared.dll /mingw64/bin/librocksdb-shared.dll &&
    cd .. &&
    rm -r rocksdb-${rocksdb_ver}
}

# Build dependencies on Linux
install_libraries_linux() {
    install_gmp_linux
    install_mpfr_linux
    install_flint_linux
}

# Build dependencies on macOS
install_libraries_macos() {
    if ! test -f /usr/local/lib/libflint.a; then
        echo "Building libflint..."
        curl -L http://www.flintlib.org/flint-${flint_vers}.tar.gz | tar xvzf - && \
        cd flint-${flint_vers} && \
        CFLAGS="-O3 -g -fexceptions -funwind-tables -fno-omit-frame-pointer" \
        ./configure \
            --prefix=/usr/local \
            --enable-static \
            --enable-tls \
        && \
        make -j 8 && \
        sudo make install && \
        cd .. && \
        rm -rf flint-${flint_vers}
        (cd /usr/local/lib && sudo install_name_tool -id '@rpath/libflint.dylib' libflint.dylib)
    fi
}

# Build dependencies on mingw
install_libraries_mingw() {
    install_flint_mingw
    install_rocksdb_mingw
}

# Install dependencies
do_builddep() {
    case "$(uname -s)" in
    Linux*)
        install_packages_linux
        install_toolchain
        install_libraries_linux
        ;;
    Darwin*)
        install_packages_macos
        install_toolchain
        install_libraries_macos
        ;;
    MSYS*|MINGW*)
        install_packages_mingw
        configure_mingw
        install_toolchain
        install_libraries_mingw
        ;;

    *)
        2>&1 echo "$0 doesn't support $(uname -s)"
        exit 1
        ;;
    esac
}

# Build release binaries
do_build() {
    do_builddep
    cargo build --bins --release
}

# Install release binaries
do_install() {
    do_build
    cargo install --bins --path .
}

# Run the test suite
do_test() {
    do_builddep
    cargo test --all
}

do_release() {
    do_builddep
    cargo build --bins --release
    mkdir -p release
    EXTENSION=""
    if [[ $1 = "win" ]]
    then
      EXTENSION=".exe"
    fi
    for bin in stegos stegosd bootstrap; do
      mv target/release/$bin$EXTENSION release/$bin-$1-x64.debug$EXTENSION;
      strip -S release/$bin-$1-x64.debug$EXTENSION -o release/$bin-$1-x64$EXTENSION;
    done

    if [[ $1 = "win" ]]
    then
      for lib in gcc_s_seh-1 rocksdb-shared stdc++-6 winpthread-1; do
        cp /mingw64/bin/lib$lib.dll ./release/
      done
      strip -S ./release/librocksdb-shared.dll
    fi
}

# Collect the code coverage information
do_coverage() {
    do_builddep
    echo "Running tests for code coverage..."
    export CARGO_INCREMENTAL=0
    export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Cinline-threshold=0 -Clink-dead-code -Coverflow-checks=off -Zno-landing-pads"
    mkdir -p $CARGO_TARGET_DIR && find $CARGO_TARGET_DIR -name '*.gc*' -delete
    cargo test --all
    zip -0 ccov.zip $(find $CARGO_TARGET_DIR -name '*.gc*' -print)
    # ignore:
    # 1) external deps.
    # 2) examples.
    # 3) test code itself.
    # 4) error wrappers.
    # 5) protobuf generated files.
    grcov ccov.zip -s . -t lcov --llvm --branch --ignore-not-existing \
        --ignore-dir "/*" \
        --ignore-dir "*/examples/**" \
        --ignore-dir "*/tests/**" \
        --ignore-dir "**/tests.rs" \
        --ignore-dir "**/error.rs" \
        --ignore-dir "${CARGO_TARGET_DIR}/debug/build/*/out/**" \
        >lcov.info
    ls -lh lcov.info
}

# Upload the code coverage information
do_coverage_push() {
    if test -z "${CODECOV_TOKEN}"; then
        2>&1 echo "Missing CODECOV_TOKEN"
        exit 1
    fi
    if test ! -f lconv.info; then
        do_coverage
    fi
    bash <(curl -s https://codecov.io/bash) -t ${CODECOV_TOKEN} -f lcov.info
}

# Build base Docker image
do_docker_base() {
    if ! docker inspect --type=image stegos/rust:${RUST_TOOLCHAIN} 2>/dev/null 1>/dev/null; then
        echo "Building stegos/rust:${RUST_TOOLCHAIN} Docker image"
        docker build --build-arg RUST_TOOLCHAIN=${RUST_TOOLCHAIN} -t stegos/rust:${RUST_TOOLCHAIN} ci-scripts/
    fi
}

# Build Docker image
do_docker() {
    do_docker_base
    echo "Building stegos/stegos:latest Docker image"
    # Check that Dockerfile has proper RUST_TOOLCHAIN
    if ! grep -q "FROM stegos/rust:${RUST_TOOLCHAIN}" Dockerfile; then
        2>&1 echo "Inconsistent ./rust-toolchain and FROM in ./Dockerfile"
        exit 1
    fi
    docker build -t stegos/stegos:latest -f Dockerfile .
}

case $1 in
    builddep|docker|docker_base|build|test|install|coverage|coverage_push|release)
        set -xe
        do_$1 $2
        ;;
    "")
        set -ve
        do_build
        ;;
    *)
        2>&1 echo "Usage: $0 builddep|docker|docker_base|build|test|install|coverage|coverage_push"
        2>&1 echo " builddep        - install the build dependencies"
        2>&1 echo " docker_base     - build Docker image for CI"
        2>&1 echo " docker          - build Docker image"
        2>&1 echo " build           - compile applications"
        2>&1 echo " test            - run the test suite"
        2>&1 echo " release         - compile and release applications"
        2>&1 echo " install         - compile and install applications"
        2>&1 echo " coverage        - generate the code coverage report"
        2>&1 echo " coverage_push   - upload the code coverage report to codecov.io"
        2>&1 echo ""
        exit 1
esac
