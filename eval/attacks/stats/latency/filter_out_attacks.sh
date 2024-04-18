#!/bin/bash

# This script is used to filter out the attack packets from all pcap files



### CONSTANTS ###
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )  # This script's path
ARP_DEFAULT="00:00:00:00:00:00"
ARP_SHA="3c:cd:5d:a2:a9:d7"
ARP_THA="50:c7:bf:ed:0a:54"
ARP_SPA="192.168.1.222"
ARP_TPA="192.168.1.135"
PCAP_FILTER="not (arp.src.hw_mac == $ARP_SHA && arp.dst.hw_mac == $ARP_DEFAULT && arp.src.proto_ipv4 == $ARP_SPA && arp.dst.proto_ipv4 == $ARP_TPA) && not (arp.src.hw_mac == $ARP_THA && arp.dst.hw_mac == $ARP_SHA && arp.src.proto_ipv4 == $ARP_TPA && arp.dst.proto_ipv4 == $ARP_SPA)"

for RAW_PCAP in "$SCRIPT_DIR"/*.raw.pcap
do
    FILTERED_PCAP="${RAW_PCAP%.raw.pcap}.pcap"
    tshark -r $RAW_PCAP -w $FILTERED_PCAP -Y "$PCAP_FILTER"
done
