#!/bin/sh

# This script regenerates the `src/ncp/ncp.rs` file from `protos/ncp.proto`.

docker run --rm -v `pwd`:/usr/code:z -w /usr/code rust /bin/bash -c " \
    apt-get update; \
    apt-get install -y protobuf-compiler; \
    cargo install --version 2.2.0 protobuf-codegen; \
    protoc --rust_out . protos/randhound_proto.proto; \
    "

mv -f randhound_proto.rs ./src/randhound_proto.rs
