from protocols.Custom import Custom

class http(Custom):
    
    # Class variables
    layer = 7               # Protocol OSI layer
    protocol_name = "http"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "method",
        "uri",
        "response"
    ]

    def parse(self, is_backward: bool = False, initiator: str = "src") -> dict:
        """
        Parse the HTTP protocol.

        :param is_backward (optional): Whether the protocol must be parsed for a backward rule.
                                       Optional, default is `False`.
        :param initiator (optional): Connection initiator (src or dst).
                                     Optional, default is "src".
        :return: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Request or response
        http_type_rule = {}
        if "response" in self.protocol_data and self.protocol_data["response"]:
            if is_backward:
                http_type_rule = {"template": "{}http_message.is_request", "match": ""}
            else:
                http_type_rule = {"template": "{}http_message.is_request", "match": "!"}
        else:
            if is_backward:
                http_type_rule = {"template": "{}http_message.is_request", "match": "!"}
            else:
                http_type_rule = {"template": "{}http_message.is_request", "match": ""}
        self.rules["nfq"].append(http_type_rule)

        # Handle HTTP method
        rule = {"forward": "http_message.method == {}"}
        # Lambda function to convert an HTTP method to its C representation (upper case)
        func = lambda http_method: f"HTTP_{http_method.upper()}"
        self.add_field("method", rule, is_backward, func)

        # Handle HTTP URI
        # URI can take two forms:
        # - Complete URI: exact string match
        # - URI prefix: string match with the beginning of the URI
        uri = self.protocol_data.get("uri", None)
        if uri is not None:
            length = len(uri) - 1 if uri.endswith("*") or uri.endswith("$") else len(uri) + 1
            rule = {"forward": f"strncmp(http_message.uri, \"{{}}\", {length}) == 0"}
            self.add_field("uri", rule, is_backward)
        
        return self.rules
