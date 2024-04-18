import logging
from typing import Tuple
import random
import scapy.all as scapy
from scapy.layers import dhcp
from packet.Packet import Packet

class BOOTP(Packet):
    """
    Class for DHCP packets.
    """

    # Class variables
    name = "BOOTP"

    # Modifiable fields
    fields = [
        "chaddr",
        "message-type"
    ]


    def __init__(self, packet: scapy.Packet, id: int = 0, last_layer_index: int = -1) -> None:
        """
        BOOTP/DHCP packet constructor.

        :param packet: Scapy Packet to be edited.
        :param id: Packet integer identifier.
        :param last_layer_index: [Optional] Index of the last layer of the packet.
                                 If not specified, it will be calculated.
        """
        super().__init__(packet, id, last_layer_index)
        self.dhcp_options = packet.getlayer("DHCP options")


    def get_dhcp_option(self, option_name) -> Tuple[str, any]:
        """
        Retrieve a DHCP option from the packet.

        :param option_name: Name of the DHCP option to retrieve.
        :return: DHCP option, as a tuple (name, value).
        """
        dhcp_options = self.dhcp_options.getfieldval("options")
        for option in dhcp_options:
            if option[0] == option_name:
                return option
            
    
    def set_dhcp_option(self, option_name, option_value) -> None:
        """
        Set a DHCP option in the packet.

        :param option_name: Name of the DHCP option to set.
        :param option_value: Value of the DHCP option to set.
        """
        dhcp_options = self.dhcp_options.getfieldval("options")
        for i in range(len(dhcp_options)):
            if dhcp_options[i][0] == option_name:
                dhcp_options[i] = option_name, option_value
                break
        self.dhcp_options.setfieldval("options", dhcp_options)


    def tweak(self) -> dict:
        """
        Randomly edit a BOOTP/DHCP field, among the following:
            - chaddr (client hardware address)
            - message-type (DHCP message type)

        :return: Dictionary containing tweak information.
        """
        # Store old hash value
        old_hash = self.get_hash()
        # Get field which will be modified
        field = random.choice(self.fields)

        # Initialize old and new values
        old_value = None
        new_value = None

        if field == "chaddr":
            old_value = self.layer.getfieldval("chaddr")  # Store old value of field
            new_value = Packet.bytes_edit_char(old_value[:6]) + old_value[6:]  # Randomly change one byte in the MAC address
            self.layer.setfieldval("chaddr", new_value)  # Set new value for field

        elif field == "message-type":
            old_value = self.get_dhcp_option(field)[1]  # Store old value of field
            # Modify field value until it is different from old value
            new_value = old_value
            while new_value == old_value:
                # Message type is an integer between 1 and 8
                new_value = random.randint(1, 8)
            self.set_dhcp_option(field, new_value)  # Set new value for field

        # Update checksums
        self.update_fields()

        # Return value: dictionary containing tweak information
        return self.get_dict_log(field, old_value, new_value, old_hash)
