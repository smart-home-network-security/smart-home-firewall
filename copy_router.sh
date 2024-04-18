#!/bin/bash

# Copy firewall, nfqueue and nflog files to router.

### CONSTANTS ###
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )  # This script's path
BIN_DIR="$SCRIPT_DIR/bin"
ROUTER_SSH="tplink"
BASE_DIR_ROUTER="/root/iot-firewall"

# Copy files for all devices
NFLOG="$BIN_DIR/nflog"
ssh $ROUTER_SSH "mkdir -p $BASE_DIR_ROUTER"
scp $NFLOG $ROUTER_SSH:$BASE_DIR_ROUTER/
for DEVICE in amazon-echo dlink-cam philips-hue smartthings-hub tplink-plug xiaomi-cam
do
    DEVICE_DIR_ROUTER="$BASE_DIR_ROUTER/$DEVICE"
    NFQUEUE="$BIN_DIR/$DEVICE"
    ssh $ROUTER_SSH "mkdir -p $DEVICE_DIR_ROUTER"
    scp $SCRIPT_DIR/devices/$DEVICE/firewall.nft $ROUTER_SSH:$DEVICE_DIR_ROUTER
    scp $NFQUEUE $ROUTER_SSH:$DEVICE_DIR_ROUTER/nfqueue
done
