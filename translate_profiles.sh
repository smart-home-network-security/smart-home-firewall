#!/bin/bash

# Translate all profiles in the devices folder into their corresponding
# pair of NFTables firewall script and NFQueue C source code.


###### VARIABLES ######

# Retrieve this script's path
# (from https://stackoverflow.com/questions/4774054/reliable-way-for-a-bash-script-to-get-the-full-path-to-itself)
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
DEVICES_DIR="$SCRIPTPATH/devices"  # Devices directory
# NFQueue IDs
NFQ_ID_START=0  # NFQueue start index
LOG_GROUP=2     # NFLog group ID


###### FUNCTIONS ######

# Print usage information
usage() {
    echo "Usage: $0 [-t] [-l log_type]" 1>&2
    exit 1
}


###### MAIN ######

# Parse command line arguments
TEST=""
LOG_TYPE=""
while getopts "tl:" opt;
do
    case "${opt}" in
        t)
            # Enable test mode
            TEST="-t"
            echo "Test mode enabled: use VM instead of router"
            ;;
        l)
            # Enable packet logging
            LOG_TYPE="${OPTARG}"
            echo "Packet logging enabled with type $LOG_TYPE"
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

# Iterate on all devices
for DEVICE in amazon-echo dlink-cam philips-hue smartthings-hub tplink-plug xiaomi-cam temperature-sensor humidity-sensor
do
    DEVICE_PATH="$DEVICES_DIR/$DEVICE"
    if [[ -d "$DEVICE_PATH" ]]
    then
        LOGGING=""
        if [[ $LOG_TYPE == "CSV" ]]
        then
            LOGGING="-l $LOG_TYPE"
        elif [[ $LOG_TYPE == "PCAP" ]]
        then
            LOGGING="-l $LOG_TYPE -g $LOG_GROUP"
        fi

        python3 "$SCRIPTPATH/src/translator/translator.py" "$DEVICE_PATH/profile.yaml" $NFQ_ID_START $TEST $LOGGING
        NFQ_ID_START=$((NFQ_ID_START+1000))
        
        if [[ $LOG_TYPE == "PCAP" ]]
        then
            LOG_GROUP=$((LOG_GROUP+1))
        fi
    fi
done
