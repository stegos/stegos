#!/usr/bin/env bash
apt-get update && apt-get install -y zip
rustup override set nightly-2019-05-23
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Cinline-threshold=0 -Clink-dead-code -Coverflow-checks=off -Zno-landing-pads"
cargo test --all
cargo install grcov -f
zip -0 ccov.zip `find . \( -name "*.gc*" \) -print`;
grcov ccov.zip -s . -t lcov --llvm --branch --ignore-not-existing \
    --ignore-dir "/*"  \
    --ignore-dir "*/examples/**"  \
    --ignore-dir "*/tests/**"  \
    --ignore-dir "**/tests.rs" \
    > lcov.info;
bash <(curl -s https://codecov.io/bash) -t ${CODECOV_TOKEN} -f lcov.info;
echo "Uploaded code coverage"
