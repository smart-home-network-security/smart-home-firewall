#!/usr/bin/python3

"""
Attack towards the `dns-query-plug-ntp` policy of the TP-Link smart plug.
Issue DNS requests for an incorrectly spelled NTP server domain name.
Packets have the following signature:
    - Source MAC address:       50:c7:bf:ed:0a:54 (TP-Link smart plug MAC address)
    - Destination MAC address:  c0:56:27:73:46:0b (gateway MAC address)
    - Source IPv4 address:      192.168.1.135 (TP-Link smart plug IPv4 address)
    - Destination IPv4 address: 192.168.1.1 (gateway IPv4 address)
    - Destination UDP port:     53 (DNS port)
    - DNS query:                "eu.pool.ntp.com" (correct would be "eu.pool.ntp.org")
All packets should be blocked.
"""

import scapy.all as scapy
import random

### GLOBAL VARIABLES ###
mac_src     = "50:c7:bf:ed:0a:54"
mac_dst     = "c0:56:27:73:46:0b"
ip_src      = "192.168.1.135"
ip_dst      = "192.168.1.1"
port_dst    = 53
qname       = "eu.pool.ntp.com"


### FUNCTIONS ###

def main():

    # Craft DNS query towards the gateway
    port_src = random.randint(1024, 65535)
    dns_query = scapy.Ether(src=mac_src, dst=mac_dst) / scapy.IP(src=ip_src, dst=ip_dst) / scapy.UDP(sport=port_src, dport=53) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname=qname))
    dns_query = dns_query.__class__(bytes(dns_query))

    # Send the DNS query
    scapy.sendp(dns_query, iface="enp0s31f6", loop=1, inter=0.001, verbose=False)


### MAIN ###
if __name__ == "__main__":
    main()
