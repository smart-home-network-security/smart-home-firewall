#!/bin/bash

# Script to run inside the cross-compilation Docker container.


# Base directory
BASE_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"


### ARGUMENTS ###

# Print usage information
usage() {
    echo "Usage: $0 ROUTER NEW_ID NEW_GID" 1>&2
    exit 1
}

# Verify number of arguments
if [[ $# -ne 2 ]] && [[ $# -ne 3 ]]; then
    usage
fi

## Get command line arguments
ROUTER=$1
NEW_UID=$2
# GID (optional)
# If not provided, equal to UID
if [[ $# -eq 2 ]]; then
    NEW_GID=$NEW_UID
elif [[ $# -eq 3 ]]; then
    NEW_GID=$3
fi


### MAIN ###

# Cross-compile sources
"$BASE_DIR"/build.sh -C "$BASE_DIR" -t "$BASE_DIR"/firewall/openwrt/$ROUTER/$ROUTER.cmake

# Change perimissions
ROOT_UID=0
for DIR in build bin; do
    DIR="$BASE_DIR"/$DIR
    find $DIR -uid $ROOT_UID -exec chown -h $NEW_UID {} \;
    find $DIR -gid $ROOT_UID -exec chgrp -h $NEW_GID {} \;
done
