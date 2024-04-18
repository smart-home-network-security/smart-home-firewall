#!/bin/bash

# This script is used to filter out the attack packets from all pcap files

### CONSTANTS ###
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )  # This script's path
PCAP_FILTER="not (ip.src == 192.168.1.135 && ip.dst == 192.168.1.1 && udp.srcport == 52476 && udp.dstport == 53 && dns.qry.name == \"eu.pool.ntp.com\")"

for RAW_PCAP in "$SCRIPT_DIR"/*.raw.pcap
do
    FILTERED_PCAP="${RAW_PCAP%.raw.pcap}.pcap"
    tshark -r $RAW_PCAP -w $FILTERED_PCAP -Y "$PCAP_FILTER"
done
