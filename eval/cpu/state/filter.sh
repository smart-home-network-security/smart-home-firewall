#!/bin/bash

# This script is used to filter out the attack packets from all pcap files

### CONSTANTS ###
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )  # This script's path
PCAP_FILTER="not (ip.src == 192.168.1.222 && ip.dst == 192.168.1.135 && tcp.srcport == 26390 && tcp.dstport == 9999 && tcp.flags.syn == 1)"

for RAW_PCAP in "$SCRIPT_DIR"/*.raw.pcap
do
    FILTERED_PCAP="${RAW_PCAP%.raw.pcap}.pcap"
    tshark -r $RAW_PCAP -w $FILTERED_PCAP -Y "$PCAP_FILTER"
done
