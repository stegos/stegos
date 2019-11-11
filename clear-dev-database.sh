#!/bin/sh

TOTAL_NODES=7

for i in $(seq -f "%02g" 1 $TOTAL_NODES); do
  echo Removing database of Node ${i}
  rm -rf dev/node${i}/chain
  rm -rf dev/node${i}/accounts/*/history
done
