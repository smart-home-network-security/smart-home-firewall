import random
import scapy.all as scapy
from scapy.layers import http
from packet.Packet import Packet

class Transport(Packet):
    """
    Transport layer (layer 4) packet, i.e. TCP or UDP.
    """

    # Modifiable fields
    fields = {
        "sport": "port",
        "dport": "port"
    }

    # Well-known ports, will be overridden by child classes
    ports = []


    def tweak(self) -> dict:
        """
        If one of the ports is a well-known port,
        randomly edit destination or source port,
        in this respective order of priority.

        :return: Dictionary containing tweak information,
                 or None if no tweak was performed.
        """
        # Store old hash value
        old_hash = self.get_hash()
        # Check if destination port is a well-known port
        if self.layer.getfieldval("dport") in self.ports:
            field = "dport"
        # Check if source port is a well-known port
        elif self.layer.getfieldval("sport") in self.ports:
            field = "sport"
        else:
            # No well-known port, do not tweak
            return None
        
        # Store old value of field
        old_value = self.layer.getfieldval(field)

        # Modify field value until it is different from old value
        new_value = old_value
        while new_value == old_value:
            # Generate a random port number between 1024 and 65535
            new_value = random.randint(1024, 65535)
        
        # Set new value for field
        self.layer.setfieldval(field, new_value)

        # Update checksums, if needed
        self.update_fields()

        # Return value: dictionary containing tweak information
        return self.get_dict_log(field, old_value, new_value, old_hash)
