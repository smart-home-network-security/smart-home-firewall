from protocols.Custom import Custom

class igmp(Custom):
    
    # Class variables
    layer = 4               # Protocol OSI layer
    protocol_name = "igmp"  # Protocol name
    l4proto = 2             # Layer 4 protocol number
    custom_parser = True    # Whether the protocol has a custom parser

    # Supported keys in YAML profile
    supported_keys = [
        "version",
        'type',
        'group'
    ]

    # Well-known groups
    groups = {
        "all":  "224.0.0.2",
        "mdns": "224.0.0.251",
        "ssdp": "239.255.255.250",
        "coap": "224.0.1.187"
    }


    def parse(self, is_backward: bool = False, initiator: str = "src") -> dict:
        """
        Parse the IGMP protocol.

        :param is_backward (optional): Whether the protocol must be parsed for a backward rule.
                                       Optional, default is `False`.
        :param initiator (optional): Connection initiator (src or dst).
                                     Optional, default is "src".
        :return: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Add protocol match
        protocol_match = {
            "template": "meta l4proto {}",
            "match": igmp.l4proto
        }
        self.rules["nft"].append(protocol_match)

        # Retrieve IGMP version
        version = self.protocol_data.get("version", 2)

        # Handle IGMP message type
        message_type = self.protocol_data["type"]
        message_type = f"V{version}_{{}}" if "report" in message_type else "{}"
        rules = {"forward": f"igmp_message.type == {message_type}"}
        # Lambda function to convert an IGMP type to its C representation (upper case and separated by underscores)
        func = lambda igmp_type: igmp_type.upper().replace(" ", "_")
        self.add_field("type", rules, is_backward, func)

        # Handle IGMP group
        if version == 3:
            # IGMPv3: consider only the first group record's multicast address
            rules = {"forward": "strcmp(ipv4_net_to_str((igmp_message.body.v3_membership_report.groups)->group_address), \"{}\") == 0"}
        else:
            # IGMPv1 and IGMPv2
            rules = {"forward": "strcmp(ipv4_net_to_str(igmp_message.body.v2_message.group_address), \"{}\") == 0"}
        # Lambda function to explicit the address of a well-known group
        func = lambda igmp_group: self.groups[igmp_group] if igmp_group in self.groups else igmp_group
        self.add_field("group", rules, is_backward, func)

        return self.rules
