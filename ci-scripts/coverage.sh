#!/usr/bin/env bash
apt-get update && apt-get install -y zip
rustup override set nightly-2019-05-23
cargo install grcov -f
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Cinline-threshold=0 -Clink-dead-code -Coverflow-checks=off -Zno-landing-pads"
cargo test --all
zip -0 ccov.zip `find . \( -name "*.gc*" \) -print`;
# ignore:
# 1) external deps.
# 2) examples.
# 3) test code itself.
# 4) error wrappers.
# 5) protobuf generated files.
grcov ccov.zip -s . -t lcov --llvm --branch --ignore-not-existing \
    --ignore-dir "/*"  \
    --ignore-dir "*/examples/**"  \
    --ignore-dir "*/tests/**"  \
    --ignore-dir "**/tests.rs" \
    --ignore-dir "**/error.rs" \
    --ignore-dir "target/debug/build/*/out/**" \
    > lcov.info;
bash <(curl -s https://codecov.io/bash) -t ${CODECOV_TOKEN} -f lcov.info;
echo "Uploaded code coverage"
