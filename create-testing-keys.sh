#!/bin/sh

set -e
NUM_KEYS=${1:-3}

rm -f stegos*.pkey stegos*.skey public-key.der private-key.pk8 genesis*.bin

# Generate wallet keys
cargo run -p stegos_node --bin bootstrap -- --keys $NUM_KEYS

mkdir -p testing
for i in `seq -f "%02g" 1 $NUM_KEYS`; do
    mkdir -p testing/ testing/node$i

    # Wallet Keys
    mv -f stegos$i.pkey testing/node$i/stegos.pkey
    mv -f stegos$i.skey testing/node$i/stegos.skey

    # Network Keys
    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -outform DER -pubout -out public-key.der
    openssl pkcs8 -in private.pem -topk8 -nocrypt -outform der -out private-key.pk8
    rm -f private.pem
    mv -f public-key.der testing/node$i/
    mv -f private-key.pk8 testing/node$i/
done

# Genesis block
mkdir -p node/data
mv genesis0.bin genesis1.bin node/data/
