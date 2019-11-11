#!/usr/bin/env bash
nodes_count=${1:-7}
# Stop all the nodes
for i in $(seq -f "%02g" 1 $nodes_count); do
  echo Removing database of Node ${i}
  rm -rf dev/node${i}/chain
  rm -rf dev/node${i}/accounts/*/history
done
