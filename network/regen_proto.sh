#!/bin/sh

# This script regenerates the `src/ncp/ncp.rs` file from `protos/ncp.proto`.

docker run --rm -v `pwd`:/usr/code:z -w /usr/code rust /bin/bash -c " \
    apt-get update; \
    apt-get install -y protobuf-compiler; \
    cargo install --version 2.1.2 protobuf-codegen; \
    protoc --rust_out . protos/ncp.proto"

mv -f ncp.rs ./src/ncp/ncp.rs
