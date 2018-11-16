#!/usr/bin/env bash

nodes_count=${1:-3}

BASE="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case $(uname -s) in
    Linux*)
        timeout_cli=timeout
        ;;
    Darwin*)
        timeout_cli=gtimeout
        ;;
    CYGWIN_NT*)
        timeout_cli=timeout
        ;;
    *)
        echo Unknown OS \"$(uname_s)\". Terminating...
        exit 127
        ;;
esac

start_timeout=30
node_id=${1:-1}

echo Starting node${node_id} ...
tmux new-session -d -s node${node_id} "rlwrap cargo run -- -c testing/node0${node_id}/stegos.toml"
${timeout_cli} ${start_timeout} sh -c 'until nc -z $0 $1 2> /dev/null; do echo "Waiting 5 sec..."; sleep 5; done' localhost $((10054+${node_id}))

if nc -z localhost $((10054+${node_id})) 2>/dev/null ; then
  echo "Ok!"
else
  echo "Couldn't connect to bootstrap node for ${start_timeout} seconds. Exiting..."
  exit 1
fi

# Start the Emotiq blockchain
for (( i=2 ; i<=${nodes_count} ; i++ )) ; do
    node_id="${i}"
    echo "Starting node=${node_id}..."
    echo tmux new-session -d -s node${node_id} "rlwrap cargo run -- -c testing/node0${node_id}/stegos.toml"
    tmux new-session -d -s node${node_id} "rlwrap cargo run -- -c testing/node0${node_id}/stegos.toml"
    tmux ls
done

for (( i=2 ; i<=${nodes_count} ; i++ )) ; do
    node_id="${i}"
    ${timeout_cli} ${start_timeout} sh -c 'until nc -z $0 $1 2> /dev/null; do echo "Waiting 5 sec..."; sleep 5; done' localhost $((10054+${node_id}))
    if nc -z localhost $((10054+${node_id})) 2>/dev/null ; then
    echo "Node '${node_id}' started!"
    else
    echo "Couldn't connect to node '${node_id}' for ${start_timeout} seconds. Exiting..."
    exit 1
    fi
done
