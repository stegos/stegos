#!/bin/sh

set -e
export NUM_KEYS=${1:-4}

# Remove old files
rm -f stegos*.pkey stegos*.skey password*.txt genesis*.bin

# Write passphrase
for i in $(seq -f "%02g" 1 $NUM_KEYS); do
    echo "dev$i" > password$i.txt
done

# Generate account keys
cargo run --bin bootstrap -- --keys $NUM_KEYS

mkdir -p testing
for i in $(seq -f "%02g" 1 $NUM_KEYS); do
    data_dir="testing/node$i"
    mkdir -p $data_dir
    rm -f password$i.txt
    if [ $i == "01" ] ; then
      mkdir -p ${data_dir}/accounts/1
      mv -f account$i.pkey ${data_dir}/accounts/1/account.pkey
      mv -f account$i.skey ${data_dir}/accounts/1/account.skey
    else
      rm account$i.?key
    fi
    mv -f network$i.pkey ${data_dir}/network.pkey
    mv -f network$i.skey ${data_dir}/network.skey
    NODE_ID=$i j2 --format=env testing/stegos.toml.j2 >testing/node$i/stegos.toml
done

# Genesis block
mkdir -p chains/dev/
mv genesis.bin chains/dev/
