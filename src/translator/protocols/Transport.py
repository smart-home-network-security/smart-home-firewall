from protocols.Protocol import Protocol

class Transport(Protocol):
    
    # Class variables
    layer = 4              # Protocol OSI layer
    custom_parser = False  # Whether the protocol has a custom parser

    # Supported keys in YAML profile
    supported_keys = [
        "src-port",
        "dst-port"
    ]

    def parse(self, is_backward: bool = False, initiator: str = "") -> dict:
        """
        Parse a layer 4 protocol.

        :param is_backward (optional): Whether the protocol must be parsed for a backward rule.
                                       Optional, default is `False`.
        :param initiator (optional): Connection initiator (src or dst).
                                     Optional, default is "src".
        :return: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Add protocol match
        protocol_match = {
            "template": "meta l4proto {}",
            "match": self.protocol_name
        }
        self.rules["nft"].append(protocol_match)

        # Connection initiator is specified
        if initiator:
            # Template rules
            template_rules = {
                "src-port": {"forward": "ct original proto-src {}", "backward": "ct original proto-dst {}"},
                "dst-port": {"forward": "ct original proto-dst  {}", "backward": "ct original proto-src {}"}
            }
            if (initiator == "src" and not is_backward) or (initiator == "dst" and is_backward):
                # Connection initiator is the source device
                self.add_field("src-port", template_rules["src-port"], is_backward)
                self.add_field("dst-port", template_rules["dst-port"], is_backward)
            elif (initiator == "src" and is_backward) or (initiator == "dst" and not is_backward):
                # Connection initiator is the destination device
                self.add_field("src-port", template_rules["dst-port"], is_backward)
                self.add_field("dst-port", template_rules["src-port"], is_backward)
        
        # Connection initiator is not specified
        else:
            # Handle source port
            rules = {"forward": self.protocol_name + " sport {}", "backward": self.protocol_name + " dport {}"}
            self.add_field("src-port", rules, is_backward)
            # Handle destination port
            rules = {"forward": self.protocol_name + " dport {}", "backward": self.protocol_name + " sport {}"}
            self.add_field("dst-port", rules, is_backward)
        
        return self.rules
