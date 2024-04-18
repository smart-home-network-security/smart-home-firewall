import random
import scapy.all as scapy
from scapy.layers import dns
from packet.DNS import DNS

class mDNS(DNS):

    # Class variables
    name = "mDNS"

    # Modifiable fields
    fields = {
        "query": [
            "qr",
            "qtype",
            "qname"
        ],
        "response": [
            "qr"
        ]
    }

    
    def __init__(self, packet: scapy.Packet, id: int = 0, last_layer_index: int = -1) -> None:
        """
        mDNS packet constructor.

        :param packet: Scapy packet to be edited.
        :param id: Packet integer identifier.
        :param last_layer_index: [Optional] Index of the last layer of the packet.
                                 If not specified, it will be calculated.
        """
        super().__init__(packet, id, last_layer_index)
        qr = self.layer.getfieldval("qr")
        self.qr_str = "query" if qr == 0 else "response"

    
    def get_field(self) -> str:
        """
        Randomly pick a DNS field to be modified.

        :return: Field name.
        """
        return random.choice(self.fields[self.qr_str])
