#!/bin/bash

# Copy PCAP traces from the router
# to this device.

### CONSTANTS ###
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )  # This script's path

### PARAMETERS ###
EXPECTED_ARGS=3
if [[ $# -ne $EXPECTED_ARGS ]]
then
    echo "Usage: $0 <router> <device> <directory>"
    exit 1
fi
ROUTER=$1
DEVICE=$2
DIR=$3
mkdir -p $SCRIPT_DIR/$DEVICE/$DIR

# Copy files
ROUTER_PATH=/tmp
for TRACE in $ROUTER_PATH/lan.pcap $ROUTER_PATH/wan.pcap $ROUTER_PATH/wlan2.4.pcap $ROUTER_PATH/wlan5.0.pcap
do
    scp $ROUTER:$TRACE $SCRIPT_DIR/$DEVICE/$DIR
    #ssh $ROUTER "rm $TRACE"
done
