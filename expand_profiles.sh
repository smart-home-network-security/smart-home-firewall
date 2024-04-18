#!/bin/bash

# Expand all profiles in the devices folder.


###### VARIABLES ######

# Retrieve this script's path
# (from https://stackoverflow.com/questions/4774054/reliable-way-for-a-bash-script-to-get-the-full-path-to-itself)
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
DEVICES_DIR="$SCRIPTPATH/devices"  # Devices directory


###### MAIN ######

# Iterate on all devices
for DEVICE in amazon-echo dlink-cam philips-hue smartthings-hub tplink-plug xiaomi-cam tuya-motion
do
    DEVICE_PATH="$DEVICES_DIR/$DEVICE"
    if [[ -d $DEVICE_PATH ]]
    then
        python3 $SCRIPTPATH/src/translator/expand.py $DEVICE_PATH/profile.yaml
    fi
done
