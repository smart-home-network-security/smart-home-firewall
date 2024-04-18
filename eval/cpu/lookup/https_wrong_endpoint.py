#!/usr/bin/python3

"""
Attack towards the `dns-https-tplinkra` policy of the TP-Link smart plug.
First, issue a DNS request for the TP-Link cloud server domain name "euw1-api.tplinkra.com",
and waits for the DNS response.
Then, issue HTTPS requests for an IP address not present in the DNS table.
Packets have the following signature:
    - Source MAC address:       50:c7:bf:ed:0a:54 (TP-Link smart plug MAC address)
    - Destination MAC address:  c0:56:27:73:46:0b (gateway MAC address)
    - Source IPv4 address:      192.168.1.135 (TP-Link smart plug IPv4 address)
    - Destination IPv4 address: 192.18.1.2    (incorrect IP address)
    - Destination UDP port:     443
All packets should be blocked.
"""

import scapy.all as scapy
import random

### GLOBAL VARIABLES ###
mac_plug    = "50:c7:bf:ed:0a:54"
mac_gateway = "c0:56:27:73:46:0b"
ip_plug     = "192.168.1.135"
ip_wrong    = "192.18.1.2"
port_https  = 443


### FUNCTIONS ###

def main():

    # Craft HTTPS packet towards the incorrect address
    port_plug = random.randint(1024, 65535)
    packet = scapy.Ether(src=mac_plug, dst=mac_gateway) / scapy.IP(src=ip_plug, dst=ip_wrong) / scapy.TCP(sport=port_plug, dport=port_https)
    packet = packet.__class__(bytes(packet))

    # Send the HTTPS packet
    scapy.sendp(packet, iface="enp0s31f6", loop=1, inter=0.001, verbose=False)



### MAIN ###
if __name__ == "__main__":
    main()
