#!/bin/bash

# Constants
TIMEOUT=5  # seconds
BIN_DIR="bin"

# Ensure globbing expands to an empty list if no matches are found
shopt -s nullglob

# Execute all NFQueue executables
for EXEC in "$BIN_DIR"/*
do
    if [ -f "$EXEC" ]
    then
        ARG=""
        if [[ "$EXEC" == *"/nflog" ]]
        then
            ARG="100"
        fi
        sudo $EXEC $ARG & sleep $TIMEOUT
        sudo kill $!
    fi
done
