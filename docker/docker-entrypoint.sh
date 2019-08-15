#!/bin/bash
set -e

if [ "$1" = 'stegosd' ]; then
    echo '/coredumps/core.%h.%e.%t' >/proc/sys/kernel/core_pattern
    ulimit -c unlimited
    exec gosu stegos "$@"
fi

exec "$@"
