#!/bin/bash

# This script is used to filter out the attack packets from all pcap files

### CONSTANTS ###
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )  # This script's path
# Timestamps
FILTER_START=170
FILTER_END=710
# Temporary PCAP files
TMP_PCAP_A="$SCRIPT_DIR/tmp_a.pcap"
TMP_PCAP_B="$SCRIPT_DIR/tmp_b.pcap"
# First/last packet prompt
FIRST_PACKET="First packet time:"
LAST_PACKET="Last packet time:"


### MAIN ###
for FULL_PCAP in "$SCRIPT_DIR"/*.all.pcap
do

    # Get all necessary packet infos
    PCAP_INFOS=$( capinfos -a -e "$FULL_PCAP" )
    # Get first packet timestamp
    PCAP_START=$( echo "$PCAP_INFOS" | grep "$FIRST_PACKET" | sed "s/$FIRST_PACKET\s*//" )
    PCAP_START_SEC=$( date -d "$PCAP_START" +"%s.%N" )
    # Get last packet timestamp
    PCAP_END=$( echo "$PCAP_INFOS" | grep "$LAST_PACKET" | sed "s/$LAST_PACKET\s*//" )
    PCAP_END_SEC=$( date -d "$PCAP_END" +"%s.%N" )
    # Get intermediate timestamps
    TIMESTAMP_A=$( echo "$PCAP_START_SEC + $FILTER_START" | bc )
    TIME_A=$( date -d "@$TIMESTAMP_A" +"%Y-%m-%d %H:%M:%S.%N" )
    TIMESTAMP_B=$( echo "$PCAP_START_SEC + $FILTER_END" | bc )
    TIME_B=$( date -d "@$TIMESTAMP_B" +"%Y-%m-%d %H:%M:%S.%N" )

    # Resulting PCAP file name
    FILTERED_PCAP="${FULL_PCAP%.all.pcap}.pcap"

    # Build temporary PCAP files
    editcap -F libpcap -A "$PCAP_START" -B "$TIME_A"   $FULL_PCAP $TMP_PCAP_A
    editcap -F libpcap -A "$TIME_B"     -B "$PCAP_END" $FULL_PCAP $TMP_PCAP_B

    # Merge temporary PCAP files
    mergecap -w $FILTERED_PCAP $TMP_PCAP_A $TMP_PCAP_B

    # Remove temporary PCAP files
    rm -f $TMP_PCAP_A $TMP_PCAP_B

done
