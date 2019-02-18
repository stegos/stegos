#!/usr/bin/env bash

wget https://github.com/SimonKagstrom/kcov/archive/v36.tar.gz
tar xzf v36.tar.gz
cd kcov-36
mkdir build
cd build 
cmake ..
make
make install
cd ../..
rm -rf kcov-36
modules='stegos
         stegos_blockchain
         stegos_consensus
         stegos_crypto
         stegos_keychain
         stegos_network
         stegos_node
         stegos_serialization
         stegos_txpool
         stegos_wallet
         '
for m in ${modules}; do 
    for file in target/debug/${m}-*[^\.d]; do 
        mkdir -p "target/cov/$(basename $file)"
        kcov --exclude-pattern=/.cargo,/usr/lib --verify "target/cov/$(basename $file)" "$file"
    done
done
bash <(curl -s https://codecov.io/bash) -t ${CODECOV_TOKEN}
echo "Uploaded code coverage"