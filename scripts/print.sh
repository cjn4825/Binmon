#!/usr/bin/env bash

# runs binmon application in background and
# cats registry.txt file every second for the user
#
# TODO: when the script exits, binmon also exits

while true; do
    printf "\n      ------ binmon ------\n"
    cat "../registryinfo/registry.txt"
    sleep 1
    clear
done
