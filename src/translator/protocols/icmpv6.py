from protocols.Protocol import Protocol

class icmpv6(Protocol):

    # Class variables
    layer = 4                 # Protocol OSI layer
    protocol_name = "icmpv6"  # Protocol name
    l4proto = 58              # Layer 4 protocol number
    custom_parser = False     # Whether the protocol has a custom parser

    # IPv6 multicast groups
    groups = {
        "multicast":         "ff02::/16",
        "all-nodes":         "ff02::1",
        "all-routers":       "ff02::2",
        "all-mldv2-routers": "ff02::16",
        "mdns":              "ff02::fb",
        "coap":              "ff02::158"
    }
    
    # Supported keys in YAML profile
    # For now, no support for ICMPv6 options, as the router does not support them
    supported_keys = []

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
        return self.rules
