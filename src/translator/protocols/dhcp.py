from protocols.Custom import Custom

class dhcp(Custom):
    
    # Class variables
    layer = 7               # Protocol OSI layer
    protocol_name = "dhcp"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "type",
        "client-mac"
    ]

    def parse(self, is_backward: bool = False, initiator: str = "src") -> dict:
        """
        Parse the DHCP protocol.

        :param is_backward (optional): Whether the protocol must be parsed for a backward rule.
                                       Optional, default is `False`.
        :param initiator (optional): Connection initiator (src or dst).
                                     Optional, default is "src".
        :return: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Handle DHCP message type
        rules = {"forward": "dhcp_message.options.message_type == {}"}
        # Lambda function to convert a DHCP type to its C representation (upper case)
        func = lambda dhcp_type: f"DHCP_{dhcp_type.upper()}"
        self.add_field("type", rules, is_backward, func)
        # Handle DHCP client MAC address
        rules = {"forward": "strcmp(mac_hex_to_str(dhcp_message.chaddr), \"{}\") == 0"}
        # Lambda function to explicit a self MAC address
        func = lambda mac: self.device['mac'] if mac == "self" else mac
        self.add_field("client-mac", rules, is_backward, func)
        return self.rules
