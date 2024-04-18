#!/usr/bin/python3

"""
Attack towards the `dns-query-plug-use1-api` policy of the TP-Link smart plug.
Issue DNS queries for an unwanted domain name.
Packets have the following signature:
    - Source MAC address:       50:c7:bf:ed:0a:54 (TP-Link smart plug MAC address)
    - Destination MAC address:  c0:56:27:73:46:0b (gateway MAC address)
    - Source IPv4 address:      192.168.1.135 (TP-Link smart plug IPv4 address)
    - Destination IPv4 address: 192.168.1.1 (gateway IPv4 address)
    - Destination UDP port:     53 (DNS port)
All packets should be blocked.
"""

import scapy.all as scapy
import random

### GLOBAL VARIABLES ###
mac_src  = "50:c7:bf:ed:0a:54"
mac_dst  = "c0:56:27:73:46:0b"
ip_src   = "192.168.1.135"
ip_dst   = "192.168.1.1"
port_dst = 53
qname    = "example.com"


### FUNCTIONS ###
def main():
    port_src = random.randint(1024, 65535)
    packet = scapy.Ether(src=mac_src, dst=mac_dst) / scapy.IP(src=ip_src, dst=ip_dst) / scapy.UDP(sport=port_src, dport=port_dst) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname=qname))
    packet = packet.__class__(bytes(packet))
    scapy.sendp(packet, iface="enp0s31f6", loop=1, inter=1, verbose=False)


### MAIN PROGRAM ###
if __name__ == "__main__":
    main()
