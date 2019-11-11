#!/usr/bin/env bash

$@

echo Finished with error code $?

while true ; do
    sleep 1
done