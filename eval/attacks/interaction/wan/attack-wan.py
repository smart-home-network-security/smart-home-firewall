#!/usr/bin/python3

"""
Attack towards the `turn-on-upon-motion-cloud` policy of the TP-Link smart plug.
Send unwanted packets having the following signature:
    - Source MAC address:       c0:56:27:73:46:0b (gateway MAC address)
    - Destination MAC address:  50:c7:bf:ed:0a:54 (TP-Link smart plug MAC address)
    - Source IPv4 address:      TP-Link cloud server IPv4 address
    - Destination IPv4 address: 192.168.1.135 (TP-Link smart plug IPv4 address)
    - Destination TCP port:     443 (HTTPS port)
All packets should be blocked, as the prerequisite door state update pattern
has not been seen beforehand.
"""

import scapy.all as scapy
import random

### GLOBAL VARIABLES ###
server_name = "use1-api.tplinkra.com"
mac_src     = "c0:56:27:73:46:0b"
mac_dst     = "50:c7:bf:ed:0a:54"
ip_dst      = "192.168.1.135"
port_src    = 443


### FUNCTIONS ###

def dns_query_server(qname: str) -> str:
    """
    Issue a DNS query for the TP-Link cloud server domain name.

    :param qname: The domain name to query.
    :return: The IPv4 address of the TP-Link cloud server.
    """
    dns_query = scapy.IP(dst="192.168.1.1") / scapy.UDP(dport=53) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname=qname))
    dns_answer = scapy.sr1(dns_query, verbose=False)
    i = 0
    dns_answer_rr = dns_answer.lastlayer().an.getlayer(i)
    while dns_answer_rr is not None:
        if dns_answer_rr.type == 1:
            return dns_answer_rr.rdata
        i += 1
        dns_answer_rr = dns_answer.lastlayer().an.getlayer(i)


def main():
    # Get the IPv4 address of the TP-Link cloud server
    ip_src = dns_query_server(server_name)
    print(f"Queried address for domain name \"{server_name}\": {ip_src}")

    # Craft HTTPS packet towards the TP-Link smart plug
    port_dst = random.randint(1024, 65535)
    packet = scapy.Ether(src=mac_src, dst=mac_dst) / scapy.IP(src=ip_src, dst=ip_dst) / scapy.TCP(sport=port_src, dport=port_dst)
    packet = packet.__class__(bytes(packet))

    # Send the HTTPS packet
    scapy.sendp(packet, iface="enp0s31f6", loop=1, inter=1, verbose=False)


### MAIN PROGRAM ###
if __name__ == "__main__":
    main()
