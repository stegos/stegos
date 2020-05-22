#!/bin/bash

#
# Create stub files (use in Dockerfile)
#

echo "fn main() {println!(\"if you see this, the build broke\")}" > build.rs

for lib in api blockchain consensus crypto keychain network node txpool replication serialization wallet crypto/stubs/vdf_field 3rdparty/gossipsub; do
    mkdir -p $PWD/${lib}/src
    echo "pub fn main() {println!(\"if you see this, the build broke\")}" > $PWD/${lib}/src/lib.rs
    echo "fn main() {println!(\"if you see this, the build broke\")}" > $PWD/${lib}/build.rs
done

for bin in stegosd stegos stegos-vault; do
    mkdir -p src/bin/${bin}
    echo "fn main() {println!(\"if you see this, the build broke\")}" > src/bin/${bin}/main.rs
done

mkdir -p $PWD/stegos_lib_test/src
echo "fn main() {println!(\"if you see this, the build broke\")}" > $PWD/stegos_lib_test/src/main.rs

mkdir -p crypto/benches
for bin in crypto/benches/bulletproofs.rs crypto/benches/scc.rs crypto/benches/pbc.rs ; do
    echo "fn main() {println!(\"if you see this, the build broke\")}" > ${bin}
done

mkdir -p blockchain/benches
for bin in blockchain/benches/block.rs blockchain/benches/election.rs ; do
    echo "fn main() {println!(\"if you see this, the build broke\")}" > ${bin}
done