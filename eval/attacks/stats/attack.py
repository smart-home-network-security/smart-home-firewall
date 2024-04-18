#!/usr/bin/python3

"""
Attack towards the `arp-plug-phone` policy of the TP-Link smart plug.
Issue ARP requests toward the smart plug with a rate higher than allowed.
Packets have the following signature:
    - Sender MAC address:  3c:cd:5d:a2:a9:d7 (phone MAC address)
    - Target MAC address:  00:00:00:00:00:00 (default MAC address)
    - Sender IPv4 address: 192.168.1.222 (phone IPv4 address)
    - Target IPv4 address: 192.168.1.135 (TP-Link smart plug IPv4 address)
Packets should be blocked when they exceed the allowed rate of 1 packet per second.
"""

import scapy.all as scapy

### GLOBAL VARIABLES ###
eth_broadcast = "ff:ff:ff:ff:ff:ff"
sha = "3c:cd:5d:a2:a9:d7"
tha = "00:00:00:00:00:00"
spa = "192.168.1.222"
tpa = "192.168.1.135"


### FUNCTIONS ###
def main():
    packet = scapy.Ether(src=sha, dst=eth_broadcast) / scapy.ARP(op=1, hwsrc=sha, hwdst=tha, psrc=spa, pdst=tpa)
    packet = packet.__class__(bytes(packet))
    scapy.sendp(packet, iface="enp0s31f6", loop=1, inter=0.1, verbose=False)


### MAIN PROGRAM ###
if __name__ == "__main__":
    main()
