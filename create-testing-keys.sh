#!/bin/sh

set -e
export NUM_KEYS=${1:-3}

rm -f stegos*.pkey stegos*.skey public-key.der private-key.pk8 genesis*.bin

# Generate wallet keys
cargo run --bin bootstrap -- --keys $NUM_KEYS

mkdir -p testing
for i in `seq -f "%02g" 1 $NUM_KEYS`; do
    mkdir -p testing/ testing/node$i

    # Wallet Keys
    mv -f stegos$i.pkey testing/node$i/stegos.pkey
    mv -f stegos$i.skey testing/node$i/stegos.skey
    NODE_ID=$i j2 --format=env testing/stegos.toml.j2 >testing/node$i/stegos.toml
done

# Genesis block
mkdir -p chains/dev/
mv genesis0.bin genesis1.bin chains/dev/
