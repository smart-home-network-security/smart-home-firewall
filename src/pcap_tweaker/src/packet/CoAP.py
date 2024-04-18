import logging
import random
import scapy.all as scapy
from scapy.contrib import coap
from packet.Packet import Packet

class CoAP(Packet):

    # Class variables
    name = "CoAP"

    # Modifiable fields
    fields = {
        "type": "int[0,3]",
        "code": "int[1,4]",
    }
    fields = [
        "type",
        "code",
        "uri"
    ]


    @staticmethod
    def new_int_value(old_value: int, start: int, end: int) -> int:
        """
        Generate a new random integer value between start and end, different from old_value.

        :param old_value: Old value of the integer.
        :param start: Start of the range.
        :param end: End of the range.
        :return: New random integer value.
        :raises ValueError: If start is greater than end.
        """
        # Invalid parameters handling
        if start > end:
            raise ValueError("Start value must be smaller than end value.")
        
        # Generate new random int value
        new_value = old_value
        while new_value == old_value:
            new_value = random.randint(start, end)
        return new_value
    

    @staticmethod
    def edit_uri(options: list) -> dict:
        """
        Randomly edit one character in each part of the URI of a CoAP packet.

        :param options: List of CoAP options.
        :return: Edited list of CoAP options.
        """
        result = {
            "new_options": [],
            "old_uri": b"",
            "new_uri": b""
        }
        for i in range(len(options)):
            if options[i][0] == "Uri-Path" or options[i][0] == "Uri-Query":
                new_value = Packet.bytes_edit_char(options[i][1])
                result["new_options"].append((options[i][0], new_value))
                prefix = b"/?" if options[i][0] == "Uri-Query" else b"/"
                result["old_uri"] += prefix + options[i][1]
                result["new_uri"] += prefix + new_value
            else:
                result["new_options"].append(options[i])
        return result


    def tweak(self) -> dict:
        """
        Randomly edit one field of the CoAP packet, among the following:
            - type
            - code
            - uri

        :return: Dictionary containing tweak information.
        """
        # Store old hash value
        old_hash = self.get_hash()
        # Get field which will be modified
        field = random.choice(self.fields)

        # Initialize old and new values
        old_value = None
        new_value = None

        # Chosen field is an integer
        if field == "type" or field == "code":
            old_value = self.layer.getfieldval(field)
            if field == "type":
                new_value = CoAP.new_int_value(old_value, 0, 3)
            elif field == "code":
                new_value = CoAP.new_int_value(old_value, 1, 4)
            self.layer.setfieldval(field, new_value)
        
        # Chosen field is the URI
        elif field == "uri":
            result = CoAP.edit_uri(self.layer.getfieldval("options"))
            old_value = result["old_uri"]
            new_value = result["new_uri"]
            self.layer.setfieldval("options", result["new_options"])
        
        # Update checksums
        self.update_fields()

        # Return value: dictionary containing tweak information
        return self.get_dict_log(field, old_value, new_value, old_hash)
