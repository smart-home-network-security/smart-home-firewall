import scapy.all as scapy
from packet.Transport import Transport

class UDP(Transport):

    # Class variables
    name = "UDP"

    # Well-known ports
    ports = [
        53,     # DNS
        5353,   # mDNS
        67,     # DHCP client
        68,     # DHCP server
        123,    # NTP
        1900,   # SSDP
        3478,   # STUN
        5683,   # CoAP
        9999,   # TP-Link
        20002,  # TP-Link
        54321   # Xiaomi
    ]
