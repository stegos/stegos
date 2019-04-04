#!/usr/bin/env bash
nodes_count=${1:-4}
# Stop all the nodes
for i in $(seq -f "%02g" 1 $nodes_count); do
  echo Stopping Node ${i}
  tmux kill-session -t node${i} 2>/dev/null
done
