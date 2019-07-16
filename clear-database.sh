#!/usr/bin/env bash
nodes_count=${1:-4}
# Stop all the nodes
for i in $(seq -f "%02g" 1 $nodes_count); do
  echo Removing database of Node ${i}
  rm -rf testing/node${i}/chain
  rm -rf testing/node${i}/accounts/*/history
done
