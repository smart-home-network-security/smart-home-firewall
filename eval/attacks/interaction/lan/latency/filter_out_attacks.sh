#!/bin/bash

# This script is used to filter out the attack packets from all pcap files


### CONSTANTS ###
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )  # This script's path
IP_SRC="192.168.1.222"
IP_DST="192.168.1.135"
TCP_DPORT="9999"
PCAP_FILTER="not (ip.addr == $IP_SRC && ip.addr == $IP_DST && tcp.dstport == $TCP_DPORT && tcp.flags.syn)"

for RAW_PCAP in "$SCRIPT_DIR"/*.raw.pcap
do
    FILTERED_PCAP="${RAW_PCAP%.raw.pcap}.pcap"
    tshark -r $RAW_PCAP -w $FILTERED_PCAP -Y "$PCAP_FILTER"
done
