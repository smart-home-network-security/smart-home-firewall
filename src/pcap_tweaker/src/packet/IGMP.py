import scapy.all as scapy
from scapy.contrib import igmp
from packet.Packet import Packet

class IGMP(Packet):
    """
    IGMP Version 2 packet.
    """

    # Class variables
    name = "IGMP"

    # Modifiable fields
    fields = {
        "type": [
            0x11,  # Membership Query
            0x12,  # Version 1 Membership Report
            0x16,  # Version 2 Membership Report
            0x17   # Leave Group
        ],
        "gaddr": "ipv4"
    }
