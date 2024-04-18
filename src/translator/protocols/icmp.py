from protocols.Protocol import Protocol

class icmp(Protocol):

    # Class variables
    layer = 4               # Protocol OSI layer
    protocol_name = "icmp"  # Protocol name
    l4proto = 1             # Layer 4 protocol number
    custom_parser = False   # Whether the protocol has a custom parser
    
    # Supported keys in YAML profile
    supported_keys = [
        "type"  # ICMP message type
    ]


    def parse(self, is_backward: bool = False, initiator: str = "src") -> dict:
        """
        Parse the ICMP protocol.

        :param is_backward (optional): Whether the protocol must be parsed for a backward rule.
                                       Optional, default is `False`.
        :param initiator (optional): Connection initiator (src or dst).
                                     Optional, default is "src".
        :return: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Add protocol match
        protocol_match = {
            "template": "meta l4proto {}",
            "match": self.l4proto
        }
        self.rules["nft"].append(protocol_match)

        # Handle ICMP message type
        icmp_rule = f"{self.protocol_name} type {{}}"
        rules = {"forward": icmp_rule, "backward": icmp_rule}
        # Lambda function to flip the ICMP type (for the backward rule)
        backward_func = lambda icmp_type: icmp_type.replace("request", "reply") if "request" in icmp_type else ( icmp_type.replace("reply", "request") if "reply" in icmp_type else icmp_type )
        self.add_field("type", rules, is_backward, backward_func=backward_func)
        return self.rules
