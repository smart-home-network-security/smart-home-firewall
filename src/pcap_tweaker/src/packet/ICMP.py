import scapy.all as scapy
from packet.Packet import Packet

class ICMP(Packet):

    # Class variables
    name = "ICMP"

    # Modifiable fields
    fields = {
        "type": [
            0,   # Echo Reply
            3,   # Destination Unreachable
            5,   # Redirect
            8,   # Echo Request
            13,  # Timestamp
            14   # Timestamp Reply
        ]  
    }
