#!/bin/sh

set -e
export NUM_KEYS=${1:-4}

# Remove old files
rm -f stegos*.pkey stegos*.skey password*.txt genesis*.bin

# Write passphrase
for i in $(seq -f "%02g" 1 $NUM_KEYS); do
    echo "dev$i" > password$i.txt
done

# Generate wallet keys
cargo run --bin bootstrap -- --keys $NUM_KEYS

mkdir -p testing
for i in $(seq -f "%02g" 1 $NUM_KEYS); do
    mkdir -p testing/ testing/node$i
    mv -f wallet$i.pkey testing/node$i/wallet.pkey
    mv -f wallet$i.skey testing/node$i/wallet.skey
    mv -f network$i.pkey testing/node$i/network.pkey
    mv -f network$i.skey testing/node$i/network.skey
    mv -f password$i.txt testing/node$i/password.txt
    NODE_ID=$i j2 --format=env testing/stegos.toml.j2 >testing/node$i/stegos.toml
done

# Genesis block
mkdir -p chains/dev/
mv genesis.bin chains/dev/
