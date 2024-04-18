import scapy.all as scapy
from packet.Packet import Packet

class ARP(Packet):

    # Class variables
    name = "ARP"

    # Modifiable fields
    fields = {
        "op": "int[1,2]",
        "hwsrc": "mac",
        "hwdst": "mac",
        "psrc": "ipv4",
        "pdst": "ipv4",
    }
