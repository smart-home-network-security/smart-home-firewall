from protocols.Custom import Custom

class dns(Custom):
    
    # Class variables
    layer = 7              # Protocol OSI layer
    protocol_name = "dns"  # Protocol name
    WILDCARD = "$"         # Wildcard character for domain names

    # Supported keys in YAML profile
    supported_keys = [
        "type",        # DNS query type
        "domain-name"  # DNS domain name
    ]


    @staticmethod
    def get_domain_name_rule(domain_name: str) -> dict:
        """
        Retrieves the NFQueue rule to match a given domain name.

        :param domain_name: Domain name to match.
        :return: Dictionary containing the NFQueue rule to match the given domain name.
        """
        if domain_name.startswith(dns.WILDCARD):
            suffix = domain_name[len(dns.WILDCARD):]
            return {
                "template": f"dns_contains_suffix_domain_name(dns_message.questions, dns_message.header.qdcount, \"{{}}\", {len(suffix)})",
                "match": suffix
            }
        else:
            return {
                "template": "dns_contains_full_domain_name(dns_message.questions, dns_message.header.qdcount, \"{}\")",
                "match": domain_name
            }


    def parse(self, is_backward: bool = False, initiator: str = "src") -> dict:
        """
        Parse the DNS protocol.

        :param is_backward (optional): Whether the protocol must be parsed for a backward rule.
                                       Optional, default is `False`.
        :param initiator (optional): Connection initiator (src or dst).
                                     Optional, default is "src".
        :return: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Handle QR flag
        qr_rules = {}
        if "response" in self.protocol_data and self.protocol_data["response"]:
            if is_backward:
                qr_rules = {"template": "dns_message.header.qr == {}", "match": 0}
            else:
                qr_rules = {"template": "dns_message.header.qr == {}", "match": 1}
        else:
            if is_backward:
                qr_rules = {"template": "dns_message.header.qr == {}", "match": 1}
            else:
                qr_rules = {"template": "dns_message.header.qr == {}", "match": 0}
        self.rules["nfq"].append(qr_rules)

        # Handle DNS query type
        rule = "( dns_message.header.qdcount > 0 && dns_message.questions->qtype == {} )"
        # Lambda function to convert an DNS query type to its C representation (upper case)
        func = lambda dns_qtype: dns_qtype.upper()
        rules = {"forward": rule, "backward": rule}
        self.add_field("qtype", rules, is_backward, func)

        # Handle DNS domain name
        domain_name = self.protocol_data.get("domain-name", None)
        if domain_name is not None:
            domain_name_rule = {}
            if isinstance(domain_name, list):
                template = []
                match = []
                for dname in domain_name:
                    single_rule = dns.get_domain_name_rule(dname)
                    template.append(single_rule["template"])
                    match.append(single_rule["match"])
                domain_name_rule = {"template": template, "match": match}
            else:
                domain_name_rule = dns.get_domain_name_rule(domain_name)
            self.rules["nfq"].append(domain_name_rule)
        
        return self.rules
