import scapy.all as scapy
from packet.Packet import Packet

class IPv4(Packet):

    # Class variables
    name = "IPv4"

    # Modifiable fields
    fields = {
        "src": "ipv4",
        "dst": "ipv4"
    }
