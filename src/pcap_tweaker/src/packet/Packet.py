from __future__ import annotations
import importlib
import logging
import string
import re
import random
from ipaddress import IPv4Address, IPv6Address
import scapy.all as scapy
import hashlib


class Packet:
    """
    Wrapper around the Scapy `Packet` class.
    """

    ##### CLASS VARIABLES #####

    # List of all alphanumerical characters
    ALPHANUM_CHARS = list(string.ascii_letters + string.digits)
    ALPHANUM_BYTES = list(bytes(string.ascii_letters + string.digits, "utf-8"))
    # Minimun payload length (in bytes)
    MIN_PAYLOAD_LENGTH = 46

    # Protocol name correspondences
    protocols = {
        "DHCP": "BOOTP"
    }

    # Modifiable fields, will be overridden by child classes
    fields = {}



    ##### STATIC METHODS #####


    @staticmethod
    def string_edit_char(s: str) -> str:
        """
        Randomly change one character in a string.

        :param s: String to be edited.
        :return: Edited string.
        """
        char = random.choice(Packet.ALPHANUM_CHARS)
        new_value = list(s)
        new_value[random.randint(0, len(new_value) - 1)] = char
        return "".join(new_value)
    

    @staticmethod
    def bytes_edit_char(s: bytes) -> bytes:
        """
        Randomly change one character in a byte array.

        :param s: Byte array to be edited.
        :return: Edited byte array.
        """
        byte = random.choice(Packet.ALPHANUM_BYTES)
        new_value = list(s)
        new_value[random.randint(0, len(new_value) - 1)] = byte
        return bytes(new_value)


    @staticmethod
    def random_mac_address() -> str:
        """
        Generate a random MAC address.

        :return: Random MAC address.
        """
        return ":".join(["%02x" % random.randint(0, 255) for _ in range(6)])


    @staticmethod
    def random_ip_address(version: int = 4) -> str:
        """
        Generate a random IP address.

        :param version: IP version (4 or 6).
        :return: Random IP address.
        :raises ValueError: If IP version is not 4 or 6.
        """
        if version == 4:
            return str(IPv4Address(random.randint(0, IPv4Address._ALL_ONES)))
        elif version == 6:
            return str(IPv6Address(random.randint(0, IPv6Address._ALL_ONES)))   
        else:
            raise ValueError("Invalid IP version (should be 4 or 6).")   


    @staticmethod
    def get_last_layer_index(packet: scapy.Packet) -> int:
        """
        Get the index of the last layer of a Scapy packet.

        :param packet: Scapy Packet.
        :return: index of the last packet layer.
        """
        i = 0
        layer = packet.getlayer(i)
        while layer is not None:
            i += 1
            layer = packet.getlayer(i)
        return i - 1


    @staticmethod
    def rebuild_packet(packet: scapy.Packet) -> scapy.Packet:
        """
        Rebuild a Scapy packet from its bytes representation,
        but keep its old timestamp.

        :param packet: Scapy packet
        :return: Rebuilt Scapy packet, with old timestamp
        """
        timestamp = packet.time
        new_packet = packet.__class__(bytes(packet))
        new_packet.time = timestamp
        return new_packet


    @classmethod
    def init_packet(c, packet: scapy.Packet, id: int = 0, last_layer_index: int = -1) -> Packet:
        """
        Factory method to create a packet of a given protocol.

        :param packet: Scapy Packet to be edited.
        :param id: [Optional] Packet integer identifier. Default is 0.
        :param last_layer_index: [Optional] Index of the last layer of the packet.
                                 If not specified, it will be calculated.
        :return: Packet of given protocol,
                 or generic Packet if protocol is not supported.
        """
        # Try creating specific packet if possible
        if last_layer_index == -1:
            last_layer_index = Packet.get_last_layer_index(packet)
        for i in range(last_layer_index, -1, -1):
            layer = packet.getlayer(i)
            try:
                protocol = layer.name.replace(" ", "_")
                if protocol == "IP" and packet.getfieldval("version") == 4:
                    # IPv4 packet
                    protocol = "IPv4"
                elif protocol == "IP" and packet.getfieldval("version") == 6:
                    # IPv6 packet
                    protocol = "IPv6"
                elif protocol == "DNS" and packet.getfieldval("sport") == 5353 and packet.getfieldval("sport") == 5353:
                    # mDNS packet
                    protocol = "mDNS"
                else:
                    protocol = Packet.protocols.get(protocol, protocol)
                module = importlib.import_module(f"packet.{protocol}")
                cls = getattr(module, protocol)
                return cls(packet, id, i)
            except ModuleNotFoundError:
                # Layer protocol not supported
                continue
        # No supported protocol found, raise ValueError
        raise ValueError(f"No supported protocol found for packet: {packet.summary()}")
    


    ##### INSTANCE METHODS #####


    def __init__(self, packet: scapy.Packet, id: int = 0, last_layer_index: int = -1) -> None:
        """
        Generic packet constructor.

        :param packet: Scapy Packet to be edited.
        :param id: Packet integer identifier.
        :param last_layer_index: [Optional] Index of the last layer of the packet.
                                 If not specified, it will be calculated.
        """
        self.id = id
        self.packet = packet
        self.layer_index = last_layer_index if last_layer_index != -1 else Packet.get_last_layer_index(packet)
        self.layer = packet.getlayer(self.name)
        if self.layer is None:
            self.layer = packet.getlayer(self.layer_index)

    
    def get_packet(self) -> scapy.Packet:
        """
        Get Scapy packet.

        :return: Scapy Packet.
        """
        return self.packet
    

    def get_length(self) -> int:
        """
        Get packet length.

        :return: Packet length.
        """
        return len(self.packet)
    

    def get_length_from_layer(self, layer: int | str) -> int:
        """
        Get packet length, starting from a given layer.

        :param layer: Layer index or name.
        :return: Packet length starting from the given layer.
        """
        return len(self.packet.getlayer(layer))
    

    def get_layer_index(self) -> int:
        """
        Get packet layer index.

        :return: Packet layer index.
        """
        return self.layer_index
    

    def get_hash(self) -> str:
        """
        Get packet payload SHA256 hash.
        The payload is first padded with null bytes to reach the minimum Ethernet payload length of 46 bytes.

        :return: Packet payload SHA256 hash.
        """
        pad_bytes_to_add = Packet.MIN_PAYLOAD_LENGTH - len(self.packet.payload)
        payload = bytes(self.packet.payload) + bytes(pad_bytes_to_add) if pad_bytes_to_add > 0 else bytes(self.packet.payload)
        return hashlib.sha256(payload).hexdigest()
    

    def rebuild(self) -> None:
        """
        Rebuild packet, but keep old timestamp.
        """
        timestamp = self.packet.time
        self.packet = self.packet.__class__(bytes(self.packet))
        self.packet.time = timestamp
    

    def update_fields(self) -> None:
        """
        Update checksum and length fields on all relevant layers,
        and rebuild packet.
        """
        # Loop on all packet layers
        i = 0
        while True:
            layer = self.packet.getlayer(i)
            if layer is None:
                break
            
            # Delete checksum field
            if hasattr(layer, "chksum") and layer.getfieldval("chksum") is not None:
                layer.delfieldval("chksum")

            # Delete length field
            if hasattr(layer, "len") and layer.getfieldval("len") is not None:
                layer.delfieldval("len")
            
            i += 1

        # Rebuild packet, to update deleted fields
        self.rebuild()

        
    def get_dict_log(self, field: str, old_value: str, new_value: str, old_hash: str) -> dict:
        """
        Log packet field modification,
        and return a dictionary containing tweak information.

        :param field: Field name.
        :param old_value: Old field value.
        :param new_value: New field value.
        :param old_hash: Old packet hash (before tweak).
        :return: Dictionary containing tweak information.
        """
        timestamp = self.packet.time
        logging.info(f"Packet {self.id}, timestamp {timestamp}: {self.name}.{field} = {old_value} -> {new_value}")
        d = {
            "id": self.id,
            "timestamp": timestamp,
            "protocol": self.name,
            "field": field,
            "old_value": old_value,
            "new_value": new_value,
            "old_hash": old_hash,
            "new_hash": self.get_hash()
        }
        return d


    def tweak(self) -> dict:
        """
        Randomly edit one packet field.

        :return: Dictionary containing tweak information,
                 or None if no tweak was performed.
        """
        # Store old hash value
        old_hash = self.get_hash()
        # Get field which will be modified
        field, value_type = random.choice(list(self.fields.items()))
        # Store old value of field
        old_value = self.layer.getfieldval(field)

        # Modify field value until it is different from old value
        new_value = old_value
        while new_value == old_value:

            if isinstance(value_type, list):
                # Field value is a list
                # Choose randomly a value from the list
                values = value_type
                new_value = old_value
                # Randomly pick new value
                new_value = random.choice(values)

            elif "int" in value_type:
                # Field value is an integer
                # Generate a random integer between given range
                if value_type == "int":
                    # No range given, default is 0-65535
                    new_value = random.randint(0, 65535)
                else:
                    # Range given
                    pattern = re.compile(r"int\[\s*(?P<start>\d+),\s*(?P<end>\d+)\s*\]")
                    match = pattern.match(value_type)
                    start = int(match.group("start"))
                    end = int(match.group("end"))
                    new_value = random.randint(start, end)

            elif value_type == "str":
                # Field value is a string
                # Randomly change one character
                new_value = Packet.string_edit_char(old_value)
            
            elif value_type == "bytes":
                # Field value is a byte array
                # Randomly change one byte
                new_value = Packet.bytes_edit_char(old_value)

            elif value_type == "port":
                # Field value is an port number
                # Generate a random port number between 1024 and 65535
                new_value = random.randint(1024, 65535)

            elif value_type == "ipv4":
                # Field value is an IPv4 address
                # Generate a random IPv4 address
                new_value = Packet.random_ip_address(version=4)

            elif value_type == "ipv6":
                # Field value is an IPv6 address
                # Generate a random IPv6 address
                new_value = Packet.random_ip_address(version=6)
            
            elif value_type == "mac":
                # Field value is a MAC address
                # Generate a random MAC address
                new_value = Packet.random_mac_address()
            
        # Set new value for field
        self.layer.setfieldval(field, new_value)

        # Update checksums
        self.update_fields()

        # Return value: dictionary containing tweak information
        return self.get_dict_log(field, old_value, new_value, old_hash)
