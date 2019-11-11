#!/bin/sh

TOTAL_NODES=7
CONSENSUS_NODES=4

set -e

mkdir -p dev/
mkdir -p chains/
for i in $(seq -f "%02g" 1 $TOTAL_NODES); do
    data_dir=dev/node$i
    account_dir1=$data_dir/accounts/1
    mkdir -p $account_dir1
    echo "dev$i" > $account_dir1/password.txt
    NODE_ID=$i NUM_KEYS=$TOTAL_NODES j2 --format=env dev/stegosd.toml.j2 >$data_dir/stegosd.toml
done

# Generate keys for $TOTAL_NODES nodes, but only $CONSENSUS_NODES in genesis.
cargo run --bin bootstrap -- --keys $TOTAL_NODES -n dev --difficulty 200 --reuse
# Overwrite $CONSENSUS_NODES
cargo run --bin bootstrap -- --keys $CONSENSUS_NODES -n dev --difficulty 200 --reuse
