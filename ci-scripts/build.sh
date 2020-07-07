#!/bin/bash
#
# CI tool
#

SCRIPT_DIR=$(
    cd "$(dirname "$0")"
    pwd -P
)

if test $(id -u) -eq 0; then
    sudo() {
        $@
    }
    # don't call sudo under root for slim docker images
fi

RUST_TOOLCHAIN=${RUST_TOOLCHAIN:-$(cat rust-toolchain)}
echo "Rust toolchain is $RUST_TOOLCHAIN"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-./target}
mkdir -p ${CARGO_TARGET_DIR}

export CFLAGS="-O3 -mtune=generic -g -fexceptions -funwind-tables -fno-omit-frame-pointer -fPIC"
export CXXFLAGS="$CFLAGS"

if test -z "${NUMCPUS}"; then
    export NUMCPUS=$(grep -c '^processor' /proc/cpuinfo)
fi

# Path to ~/Downloads to save all downloaded tarballs.
DOWNLOADS=$(xdg-user-dir DOWNLOAD 2>/dev/null || echo $HOME/Downloads)

# Android options.
ANDROID_SDK_URL=https://dl.google.com/android/repository/sdk-tools-linux-4333796.zip
ANDROID_SDK_TARBALL=$(basename $ANDROID_SDK_URL)
ANDROID_SDK_DIR=${ANDROID_HOME:-$HOME/Android/Sdk}
ANDROID_API_LEVEL=21

configure_mingw() {
    echo "Found Win-GNU, setting tar to local, and sudo to nothing"
    shopt -s expand_aliases
    alias tar=/usr/bin/tar

    #don't call sudo and ldconfig under mingw
    sudo() {
        $@
    }
    ldconfig() {
        $@
    }

    export PATH=/c/msys64/mingw64/bin:$PATH
    export HOME=$(cygpath -u $USERPROFILE)
    export RUSTUP_TOOLCHAIN=$RUST_TOOLCHAIN-x86_64-pc-windows-gnu
    export CPATH=/mingw64/include/
    export FLINT_LIB_DIR=/mingw64/lib
    export SNAPPY_LIB_DIR=/mingw64/lib
    export ZSTD_LIB_DIR=/mingw64/lib
    export LZ4_LIB_DIR=/mingw64/lib
    # uncomment if we need shared version of rocksdb installed
#    export ROCKSDB_LIB_DIR=/mingw64/lib
    export SNAPPY_STATIC
    export ZSTD_STATIC
    export LZ4_STATIC
}

# Install dependencies on Linux via apt
install_packages_linux() {
    if test -f /etc/debian_version; then
        echo "Installing dependencies using apt..."
        export DEBIAN_FRONTEND=noninteractive
        sudo apt-get update &&
            sudo apt-get install -y \
                binutils-dev \
                build-essential \
                libc6-dev-i386 \
                m4 \
                clang \
                curl \
                git \
                gzip \
                libiberty-dev \
                libssl-dev \
                openjdk-8-jdk-headless \
                pkg-config \
                tar \
                zip \
                zlib1g-dev
    elif test -f /etc/redhat-release; then
        sudo yum install -y \
            binutils-devel \
            clang \
            curl \
            gcc \
            gcc-c++ \
            git \
            gzip \
            kernel-devel \
            make \
            m4 \
            openssl-devel \
            java-1.8.0-openjdk-headless \
            pkg-config \
            tar \
            zip \
            zlib-devel
    elif test -f /etc/arch-release; then
        sudo pacman -S --noconfirm --needed \
            binutils \
            clang \
            curl \
            gcc \
            git \
            gzip \
            linux-headers \
            make \
            m4 \
            openssl \
            jdk8-openjdk \
            pkg-config \
            tar \
            zip \
            zlib      
    else 
        echo 2>&1 "Unsupported Linux distro"
        exit 1
    fi
}

install_packages_macos() {
    if ! clang -v; then
        echo 2>&1 "Please install Command Line Tools:"
        echo 2>&1 "xcode-select --install"
        exit 1
    fi
}

install_packages_mingw() {
    LLVM_VERSION=10.0.0-1
    GCC_VERSION=9.2.0-2
    MINGW_URL=http://repo.msys2.org/mingw/x86_64/mingw-w64-x86_64
    PEXT=any.pkg.tar.xz


    # mingw-gcc set _mingw_ target during compile, while msys-gcc set to gnuc.
    # And some libraryes didn't understands OS.
    # Thats why install gcc set from mingw repos.
    # Also install building dependencies for rocksdb.

    pacman -S --noconfirm --needed mingw-w64-x86_64-gflags \
        mingw-w64-x86_64-zlib \
        mingw-w64-x86_64-zstd \
        mingw-w64-x86_64-lz4 \
        mingw-w64-x86_64-snappy \
        mingw-w64-x86_64-cmake \
        m4 make diffutils curl patch tar zip

    URL_VER=$LLVM_VERSION-$PEXT
    #downgrade clang to specific versions for bindgen
    pacman -U --noconfirm --needed $MINGW_URL-clang-$URL_VER $MINGW_URL-llvm-$URL_VER

    # Upgrade gcc version to 9.2.0, because 8.3 cannot build libbactrace during building of rocksdb.
    URL_VER=$GCC_VERSION-$PEXT
    pacman -U --noconfirm --needed $MINGW_URL-gcc-$URL_VER $MINGW_URL-gcc-libs-$URL_VER $MINGW_URL-gcc-ada-$URL_VER \
    $MINGW_URL-gcc-libgfortran-$URL_VER $MINGW_URL-gcc-fortran-$URL_VER $MINGW_URL-gcc-objc-$URL_VER


}

patch_mingw_toolchain() {
      # Currently rust for GNU support outdated toolchain (with gcc 6.3.0)
    # this patch will partially upgrade toolchain to new from local gcc
    rust_path="$HOME/.rustup/toolchains/${RUST_TOOLCHAIN}-x86_64-pc-windows-gnu/lib/rustlib/x86_64-pc-windows-gnu"
    echo "Patching Rust toolchain gcc"
    for mingw_file in gcc.exe ld.exe; do
      cp /mingw64/bin/$mingw_file $rust_path/bin
    done

    for mingw_file in "x86_64-w64-mingw32/lib/libshlwapi.a" lib/gcc/x86_64-w64-mingw32/9.2.0/libstdc++.a; do
      cp /mingw64/$mingw_file $rust_path/lib/
    done

    
}

# Installs Android toolchain.
install_android_toolchain() {
    platform=$(uname -s)
    case "$platform" in
    Linux*) ;;

    *)
        echo 2>&1 "Platform $platform is not supported"
        ;;
    esac
    echo ANDROID_SDK_DIR = $ANDROID_SDK_DIR
    if test ! -x $ANDROID_SDK_DIR/tools/bin/sdkmanager; then
        echo "Install Android SDK"
        if test ! -f $DOWNLOADS/$ANDROID_SDK_TARBALL; then
            mkdir -p $DOWNLOADS $ANDROID_SDK_DIR
            curl -L $ANDROID_SDK_URL -o $DOWNLOADS/$ANDROID_SDK_TARBALL
        fi
        mkdir -p $ANDROID_SDK_DIR
        unzip $DOWNLOADS/$ANDROID_SDK_TARBALL -d $ANDROID_SDK_DIR
        chmod a+x $ANDROID_SDK_DIR/tools/bin/*
    fi
    sdkmanager() {
        $ANDROID_SDK_DIR/tools/bin/sdkmanager "$@"
    }
    bindir=$ANDROID_SDK_DIR/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin
    if test ! -d $bindir; then
        echo "Install Android NDK, build-tools, etc."
        yes | sdkmanager --licenses
        sdkmanager "build-tools;29.0.2" "platform-tools" "platforms;android-$ANDROID_API_LEVEL" "ndk-bundle"
        echo "export PATH=\$PATH:$bindir" >>~/.profile
    fi
    export PATH=$PATH:$bindir
    for triplet in armv7a-linux-androideabi aarch64-linux-android i686-linux-android x86_64-linux-android; do
        if test ! -x $bindir/$triplet-gcc; then
            echo "Create symlinks for $triplet"
            (
                cd $bindir
                sudo ln -sf $triplet$ANDROID_API_LEVEL-clang $triplet-clang
                sudo ln -sf $triplet$ANDROID_API_LEVEL-clang $triplet-gcc
                sudo ln -sf $triplet$ANDROID_API_LEVEL-clang++ $triplet-clang++
                sudo ln -sf $triplet$ANDROID_API_LEVEL-clang++ $triplet-g++
            )
        fi
        sudo cp -pf $SCRIPT_DIR/rustlinker $bindir/$triplet-rustlinker
        $triplet-gcc --version
    done

    for target in aarch64-linux-android arm-linux-androideabi armv7-linux-androideabi i686-linux-android x86_64-linux-android; do
        rustup target add $target
    done

    if ! grep android ~/.cargo/config &>/dev/null; then
        echo "Configure Cargo for Android"
        mkdir -p ~/.cargo
        cp -p $SCRIPT_DIR/cargo-config ~/.cargo/config
    fi
}
# Install Rust toolchain via rustup
install_toolchain() {
    export PATH="$HOME/.cargo/bin:$PATH"
    if ! rustup show | grep -q ${RUST_TOOLCHAIN}; then
        echo "Installing Rust ${RUST_TOOLCHAIN}"
        curl -L https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_TOOLCHAIN}
        rustup show
        rustc --version
    fi

    if ! rustfmt --version >/dev/null; then
        echo "Installing rustfmt"
        # allow for non-existent rustfmt (nightly ARM65)
        # does not affect production build
        rustup component add rustfmt || true
    fi
}

# Install dependencies
do_builddep() {
    case "$(uname -s)" in
    Linux*)
        install_packages_linux
        install_toolchain
        if test -n "$WITH_ANDROID"; then
            install_android_toolchain
        fi
        ;;
    Darwin*)
        install_packages_macos
        install_toolchain
        ;;
    MSYS* | MINGW*)
        install_packages_mingw
        configure_mingw
        install_toolchain
        patch_mingw_toolchain
        ;;

    *)
        echo 2>&1 "$0 doesn't support $(uname -s)"
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

do_build_release() {
    #
    # Set enviroment variables
    #

    do_builddep
    extension=""
    dylib="libstegos.so"
    strip="strip"
    case $1 in
    linux-x64)
        target=x86_64-unknown-linux-gnu
        ;;
    macos-x64)
        target=x86_64-apple-darwin
        dylib="libstegos.dylib"
        ;;
    win-x64)
        target=x86_64-pc-windows-gnu
        extension=".exe"
        dylib="stegos.dll"
        ;;
    android-x64)
        install_android_toolchain
        target=x86_64-linux-android
        strip=x86_64-linux-android-strip
        # ignore sccache
        unset CC CXX
        export CC CXX
        ;;
    android-aarch64)
        install_android_toolchain
        target=aarch64-linux-android
        strip=aarch64-linux-android-strip
        # ignore sccache
        unset CC CXX
        export CC CXX
        ;;
    *)
        echo 2>&1 "Unknown platform: $1"
        exit 1
        ;;
    esac

    #
    # Build release
    #

    rustup target add $target
    cargo build --bins --lib --release --target $target
    ls -lah target/$target/release

    #
    # Create generic artifacts
    #

    mkdir -p artifacts
    for bin in stegos stegosd bootstrap; do
        mv target/$target/release/$bin$extension artifacts/$bin.debug$extension
        $strip -S artifacts/$bin.debug$extension -o artifacts/$bin$extension
    done
    mv target/$target/release/$dylib artifacts/$dylib.debug
    $strip -S artifacts/$dylib.debug -o artifacts/$dylib


    ls -lah artifacts

    mkdir -p release
    case $1 in
    linux-x64 | macos-x64)
        files=()
        for bin in stegos stegosd; do
            files+=("$bin$extension")
        done
        tar -czvf release/stegos.tar.gz -C artifacts "${files[@]}"
        ;;
    win-x64)
        for bin in stegos stegosd; do
            zip release/stegos.zip -j artifacts/$bin$extension
        done

        for lib in gcc_s_seh-1 lz4 zstd snappy stdc++-6 winpthread-1; do
            zip release/stegos.zip -j /mingw64/bin/lib$lib.dll
        done
        ;;
    android-x64)
        cp $ANDROID_SDK_DIR/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/x86_64-linux-android/libc++_shared.so ./artifacts
        tar -czvf release/libstegos.tar.gz -C artifacts $dylib libc++_shared.so

        ;;
    android-aarch64)

        cp $ANDROID_SDK_DIR/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so ./artifacts
        tar -czvf release/libstegos.tar.gz  -C artifacts $dylib libc++_shared.so
        ;;
    *)
        echo 2>&1 "Unknown platform: $1"
        exit 1
        ;;
    esac

    
    ls -lah release
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
    # 3) other bins.
    # 4) test code itself.
    # 5) error wrappers.
    # 6) protobuf generated files.
    grcov ccov.zip -s . -t lcov --llvm --branch --ignore-not-existing \
        --ignore "/*" \
        --ignore "*/examples/**" \
        --ignore "*/bins/**" \
        --ignore "*/tests/**" \
        --ignore "**/tests.rs" \
        --ignore "**/error.rs" \
        --ignore "${CARGO_TARGET_DIR}/debug/build/*/out/**" \
        >lcov.info
    ls -lh lcov.info
}

# Upload the code coverage information
do_coverage_push() {
    if test -z "${CODECOV_TOKEN}"; then
        echo 2>&1 "Missing CODECOV_TOKEN"
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
        echo "Building quay.io/stegos/rust:${RUST_TOOLCHAIN} Docker image"
        docker build -t quay.io/stegos/rust:${RUST_TOOLCHAIN} $SCRIPT_DIR
    fi
}

# Build Docker image
do_docker() {
    do_docker_base
    echo "Building quay.io/stegos/stegos:latest Docker image"
    # Check that Dockerfile has proper RUST_TOOLCHAIN
    if ! grep -q "FROM quay.io/stegos/rust:${RUST_TOOLCHAIN}" Dockerfile; then
        echo 2>&1 "Inconsistent ./rust-toolchain and FROM in ./Dockerfile"
        exit 1
    fi
    docker build -t quay.io/stegos/stegos:latest -f Dockerfile $SCRIPT_DIR
}

case $1 in
builddep | androiddep | docker | docker_base | build | test | install | coverage | coverage_push | build_release)
    set -xe
    do_$1 $2
    ;;
"")
    set -xe
    do_build
    ;;
*)
    echo 2>&1 "Usage: $0 builddep|docker|docker_base|build|test|install|coverage|coverage_push"
    echo 2>&1 " builddep        - install the build dependencies"
    echo 2>&1 "     WITH_ANDROID=1     with Android toolchain"
    echo 2>&1 " docker_base     - build Docker image for CI"
    echo 2>&1 " docker          - build Docker image"
    echo 2>&1 " build           - compile applications"
    echo 2>&1 " test            - run the test suite"
    echo 2>&1 " release         - compile and release applications"
    echo 2>&1 " install         - compile and install applications"
    echo 2>&1 " coverage        - generate the code coverage report"
    echo 2>&1 " coverage_push   - upload the code coverage report to codecov.io"
    echo 2>&1 ""
    exit 1
    ;;
esac
