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
    data_dir="testing/node$i/data"
    rm -f password$i.txt
    mkdir -p ${data_dir}/wallets
    mv -f wallet$i.pkey ${data_dir}/wallets/1.pkey
    mv -f wallet$i.skey ${data_dir}/wallets/1.skey
    mv -f network$i.pkey ${data_dir}/network.pkey
    mv -f network$i.skey ${data_dir}/network.skey
    NODE_ID=$i j2 --format=env testing/stegos.toml.j2 >testing/node$i/stegos.toml
done

# Genesis block
mkdir -p chains/dev/
mv genesis.bin chains/dev/
