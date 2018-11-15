#!/bin/sh

# This script regenerates the `src/ncp/ncp.rs` file from `protos/ncp.proto`.

docker run --rm -v `pwd`:/usr/code:z -w /usr/code rust /bin/bash -c " \
    apt-get update; \
    apt-get install -y protobuf-compiler; \
    cargo install --version 2.1.4 protobuf-codegen; \
    protoc --rust_out . protos/ncp.proto; \
    protoc --rust_out . protos/heartbeat_proto.proto \
    "

mv -f ncp.rs ./src/ncp/ncp.rs
mv -f heartbeat_proto.rs ./src/node/heartbeat/heartbeat_proto.rs
