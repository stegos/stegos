#!/bin/sh

set -e
export NUM_KEYS=${1:-4}

export CHAIN_NAME=$2
[[ -z $CHAIN_NAME ]] && export CHAIN_NAME="dev"

# Remove old files
rm -f stegos*.pkey stegos*.skey password*.txt genesis*.bin

# Write passphrase
for i in $(seq -f "%02g" 1 $NUM_KEYS); do
    echo "dev$i" > password$i.txt
done

# Generate account keys
cargo run --bin bootstrap -- --keys $NUM_KEYS -n $CHAIN_NAME --difficulty 200

mkdir -p testing
for i in $(seq -f "%02g" 1 $NUM_KEYS); do
    data_dir="testing/node$i"
    mkdir -p ${data_dir}/accounts/1
    mv -f account$i.pkey ${data_dir}/accounts/1/account.pkey
    mv -f account$i.skey ${data_dir}/accounts/1/account.skey
    mv -f network$i.pkey ${data_dir}/network.pkey
    mv -f network$i.skey ${data_dir}/network.skey
    rm password$i.txt
    NODE_ID=$i j2 --format=env testing/stegosd.toml.j2 >testing/node$i/stegosd.toml
done

# Genesis block
mkdir -p chains/dev/
mv genesis.bin chains/dev/
