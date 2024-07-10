from typing import Union
import ipaddress
from protocols.Protocol import Protocol
from protocols.igmp import igmp

class ip(Protocol):

    # Class variables
    layer = 3              # Protocol OSI layer
    custom_parser = False  # Whether the protocol has a custom parser
    
    # Supported keys in YAML profile
    supported_keys = [
        "src",
        "dst"
    ]

    # Well-known addresses
    addrs = {
        "ipv4": {
            "local":         "192.168.0.0/16",
            "external":      "!= 192.168.0.0/16",
            "gateway":       "192.168.1.1",
            "phone":         "192.168.1.222",
            "broadcast":     "255.255.255.255",
            "udp-broadcast": "192.168.1.255",
            "igmpv3":        "224.0.0.22",
            **igmp.groups
        },
        "ipv6": {
            "default":       "::",
            "local":         ["fe80::/10", "fc00::/7"],
            "gateway":       "fddd:ed18:f05b::1",
            "gateway-local": "fe80::c256:27ff:fe73:460b",
            "phone":         "fe80::db22:fbec:a6b4:44fe",
        }
    }

    @staticmethod
    def is_ip_static(addr: Union[str, list], version: str = "ipv4") -> bool:
        """
        Check whether a (list of) string is a well-known IP alias or an explicit IP address.

        :param addr: (list of) string to check.
        :param version: IP version (ipv4 or ipv6). Default is "ipv4".
        :return: True if the (list of) string is an IP address, False otherwise.
        """
        if type(addr) == list:
            # List of addresses
            return all([ip.is_ip_static(a) for a in addr])
        
        # Single address
        if addr == "self" or addr in ip.addrs[version]:
            # Address is a well-known alias
            return True
        # Address is not a well-known alias
        try:
            ipaddress.ip_address(addr)
            return True
        except ValueError:
            # Address is not an explicit address
            return False


    def is_ip(self, addr: Union[str, list]) -> bool:
        """
        Check whether a (list of) string is a well-known IP alias or an explicit IP address.

        :param addr: (list of) string to check.
        :return: True if the (list of) string is an IP address, False otherwise.
        """
        if type(addr) == list:
            # List of addresses
            return all([self.is_ip(a) for a in addr])
        
        # Single address
        if addr == "self" or addr in self.addrs:
            # Address is a well-known alias
            return True
        
        # Address is not a well-known alias
        
        try:
            ipaddress.ip_network(addr)
        except ValueError:
            # Address is not an explicit address or CIDR subnet
            return False
        else:
            # Address is an explicit address or CIDR subnet
            return True


    def explicit_address(self, addr: Union[str,list]) -> str:
        """
        Return the explicit version of an IP address alias,
        or a list of IP address aliases.
        Example: "local" -> "192.168.0.0/16"

        :param addr: IP address alias(es) to explicit.
        :return: Explicit IP address(es).
        :raises ValueError: If the address is not a well-known alias or an explicit address.
        """
        # First check if address(es) correspond(s) to well-known alias(es)
        if not self.is_ip(addr):
            # Address(es) is/are invalid
            raise ValueError(f"Unknown address: {str(addr)}")

        # Check if given address(es) is/are a list
        if isinstance(addr, list):
            # List of IP address aliases, process each of them
            return self.format_list([self.explicit_address(a) for a in addr])
        
        # Single IP address alias
        
        # Address is valid
        if addr == "self":
            # Address is "self"
            return self.device[self.protocol_name]
        elif addr in self.addrs:
            # Address is a well-known address alias
            explicit = self.addrs[addr]
            if type(explicit) == list:
                # List of corresponding explicit addresses
                return self.format_list(explicit)
            else:
                # Single corresponding explicit address
                return explicit
        else:
            # Address is an explicit address
            return addr

    
    def add_addr_nfqueue(self, addr_dir: str, is_backward: bool = False) -> None:
        """
        Add a new IP address match to the nfqueue accumulator.

        :param addr_dir: Address direction to add the rule to (src or dst)
        :param is_backward: Whether the field to add is for a backward rule.
        """
        other_dir = "src" if addr_dir == "dst" else "dst"
        version = int(self.protocol_name[3])
        # Parts of the rules
        domain_name_rule_prefix = "dns_entry_contains(dns_map_get(dns_map, \"{}\"), (ip_addr_t) {{.version = " + str(version) + ", .value." + self.protocol_name + " = get_" + self.protocol_name + "_"
        domain_name_rule_prefix = "dns_entry_contains(dns_map_get(dns_map, \"{}\"), (ip_addr_t) {{.version = " + str(version) + ", .value." + self.protocol_name + " = "
        domain_name_rule_suffix = "_addr}})"
        ip_addr_rule_prefix = "compare_ip((ip_addr_t) {{.version = " + str(version) + ", .value." + self.protocol_name + " = "
        ip_addr_rule_suffix = "_addr(payload)}}, ip_str_to_net(\"{}\", " + str(version) + "))"
        cached_ip_rule_suffix = "_addr}}, interactions_data[{}].cached_ip)"
        # Template rules for a domain name
        rules_domain_name = {
            "forward": "( " + ip_addr_rule_prefix + addr_dir + cached_ip_rule_suffix + " || " + domain_name_rule_prefix + addr_dir + domain_name_rule_suffix + " )",
            "backward": "( " + ip_addr_rule_prefix + other_dir + cached_ip_rule_suffix + " || " + domain_name_rule_prefix + other_dir + domain_name_rule_suffix + " )"
        }
        # Template rules for an IP address
        rules_address = {
            "forward": ip_addr_rule_prefix + addr_dir + ip_addr_rule_suffix,
            "backward": ip_addr_rule_prefix + other_dir + ip_addr_rule_suffix
        }

        value = self.protocol_data[addr_dir]
        rules = {}
        # If value from YAML profile is a list, produce disjunction of all elements
        if isinstance(value, list):
            template = []
            match = []
            # Value is a list
            for v in value:
                is_ip = self.is_ip(v)
                template_rules = rules_address if is_ip else rules_domain_name
                func = self.explicit_address if is_ip else lambda x: x
                match.append(func(v))
                if not is_backward:
                    template.append(template_rules["forward"])
                elif is_backward and "backward" in template_rules:
                    template.append(template_rules["backward"])
            rules = {"template": template, "match": match}
        else:
            # Value is a single element
            is_ip = self.is_ip(value)
            template_rules = rules_address if is_ip else rules_domain_name
            func = self.explicit_address if is_ip else lambda x: x
            if not is_backward:
                rules = {"template": template_rules["forward"], "match": func(value)}
            elif is_backward and "backward" in template_rules:
                rules = {"template": template_rules["backward"], "match": func(value)}

        # Append rules
        if rules:
            self.rules["nfq"].append(rules)
            
    
    def add_addr(self, addr_dir: str, is_backward: bool = False, initiator: str = "") -> None:
        """
        Add a new IP address match to the accumulator, in two possible ways:
            - If the address is a well-known alias or an explicit IP address, add an nftables match.
            - If the address is a domain name, add an nfqueue match.

        :param addr_dir: Address direction to add the rule to (src or dst)
        :param is_backward: Whether the field to add is for a backward rule.
        :param initiator: Optional, initiator of the connection (src or dst).
        """
        other_dir = "src" if addr_dir == "dst" else "dst"
        addr = self.protocol_data[addr_dir]

        if self.is_ip(addr):  # Source address is a well-known alias or an explicit IP address
            tpl_addr_matches = {
                "src": "saddr {}",
                "dst": "daddr {}"
            }
            if initiator:  # Connection initiator is specified
                if (initiator == "src" and not is_backward) or (initiator == "dst" and is_backward):
                    # Connection initiator is the source device
                    rules = {
                        "forward": f"ct original {self.nft_prefix} {tpl_addr_matches[addr_dir]}",
                        "backward": f"ct original {self.nft_prefix} {tpl_addr_matches[other_dir]}"
                    }
                elif (initiator == "src" and is_backward) or (initiator == "dst" and not is_backward):
                    # Connection initiator is the destination device
                    rules = {
                        "forward": f"ct original {self.nft_prefix} {tpl_addr_matches[other_dir]}",
                        "backward": f"ct original {self.nft_prefix} {tpl_addr_matches[addr_dir]}"
                    }
            
            else:  # Connection initiator is not specified
                rules = {"forward": f"{self.nft_prefix} {tpl_addr_matches[addr_dir]}", "backward": f"{self.nft_prefix} {tpl_addr_matches[other_dir]}"}
            
            self.add_field(addr_dir, rules, is_backward, self.explicit_address)

        else:  # Source address is potentially a domain name
            self.add_addr_nfqueue(addr_dir, is_backward)


    def parse(self, is_backward: bool = False, initiator: str = "") -> dict:
        """
        Parse the IP (v4 or v6) protocol.

        :param is_backward (optional): Whether the protocol must be parsed for a backward rule.
                                       Optional, default is `False`.
        :param initiator (optional): Connection initiator (src or dst).
                                     Optional, default is "src".
        :return: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        if "src" in self.protocol_data:
            # Source address is specified
            self.add_addr("src", is_backward, initiator)
        if "dst" in self.protocol_data:
            # Destination address is specified
            self.add_addr("dst", is_backward, initiator)
        return self.rules
