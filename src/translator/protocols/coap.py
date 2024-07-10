from protocols.Custom import Custom

class coap(Custom):
    
    # Class variables
    layer = 7               # Protocol OSI layer
    protocol_name = "coap"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "type",
        "method",
        "uri"
    ]

    def parse(self, is_backward: bool = False, initiator: str = "src") -> dict:
        """
        Parse the CoAP protocol.

        :param is_backward (optional): Whether the protocol must be parsed for a backward rule.
                                       Optional, default is `False`.
        :param initiator (optional): Connection initiator (src or dst).
                                     Optional, default is "src".
        :return: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Lambda functions to convert a CoAP type or method to its C representation (upper case and separated by underscores)
        func_coap_type = lambda type: f"COAP_{type.upper().replace('-', '_')}"
        func_coap_method = lambda method: f"HTTP_{method.upper().replace('-', '_')}"

        # Handle CoAP message type
        rule = {"forward": "coap_message.type == {}"}
        self.add_field("type", rule, is_backward, func_coap_type)

        # Handle CoAP method
        rule = {"forward": "coap_message.method == {}"}
        self.add_field("method", rule, is_backward, func_coap_method)

        # Handle CoAP URI
        rule = {"forward": "strcmp(coap_message.uri, \"{}\") == 0"}
        self.add_field("uri", rule, is_backward)
        
        return self.rules
