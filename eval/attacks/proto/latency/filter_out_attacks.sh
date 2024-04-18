#!/bin/bash

# This script is used to filter out the attack packets from all pcap files



### CONSTANTS ###
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )  # This script's path
IP_SRC="192.168.1.135"
IP_DST="192.168.1.1"
UDP_DPORT="53"
DNS_QNAME="example.com"
PCAP_FILTER="not (ip.addr == $IP_SRC && ip.addr == $IP_DST && udp.port == $UDP_DPORT && dns.qry.name == \"$DNS_QNAME\")"

for RAW_PCAP in "$SCRIPT_DIR"/*.raw.pcap
do
    FILTERED_PCAP="${RAW_PCAP%.raw.pcap}.pcap"
    tshark -r $RAW_PCAP -w $FILTERED_PCAP -Y "$PCAP_FILTER"
done
