#!/usr/bin/env bash

mode=${2:-debug}
nodes_count=${1:-4}

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
node_id=01

echo Starting node${node_id} ...
tmux new-session -d -s node${node_id} "dev/waiter.sh target/${mode}/stegosd -c dev/node${node_id}/stegosd.toml"
${timeout_cli} ${start_timeout} sh -c 'until nc -z $0 $1 2> /dev/null; do echo "Waiting 5 sec..."; sleep 5; done' localhost $((3144 + ${node_id}))

if nc -z localhost $((3144 + ${node_id})) 2>/dev/null; then
    echo "Ok!"
    sleep 2
else
    echo "Couldn't connect to bootstrap node for ${start_timeout} seconds. Exiting..."
    exit 1
fi

# Start the Emotiq blockchain
for i in $(seq -f "%02g" 2 $nodes_count); do
    node_id="${i}"
    echo "Starting node=${node_id}..."
    # echo tmux new-session -d -s node${node_id} "testing/waiter.sh target/${mode}/stegos -c testing/node${node_id}/stegosd.toml"
    tmux new-session -d -s node${node_id} "dev/waiter.sh target/${mode}/stegosd -c dev/node${node_id}/stegosd.toml"
    ${timeout_cli} ${start_timeout} sh -c 'until nc -z $0 $1 2> /dev/null; do echo "Waiting 5 sec..."; sleep 2; done' localhost $((3144 + ${node_id}))
    if nc -z localhost $((3144 + ${node_id})) 2>/dev/null; then
        echo "Node '${node_id}' started!"
        sleep 2
    else
        echo "Couldn't connect to node '${node_id}' for ${start_timeout} seconds. Exiting..."
        exit 1
    fi
    tmux ls
done
