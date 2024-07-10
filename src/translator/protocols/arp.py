from protocols.Protocol import Protocol

class arp(Protocol):

    # Class variables
    protocol_name = "arp"  # Protocol name
    layer = 3              # Protocol OSI layer
    custom_parser = False  # Whether the protocol has a custom parser
    
    # Supported keys in YAML profile
    supported_keys = [
        "type",  # ARP message type
        "sha",   # ARP source hardware address
        "tha",   # ARP target hardware address
        "spa",   # ARP source protocol address
        "tpa"    # ARP target protocol address
    ]

    # Well-known addresses
    mac_addrs = {
        "gateway": "c0:56:27:73:46:0b",
        "default": "00:00:00:00:00:00",
        "broadcast": "ff:ff:ff:ff:ff:ff",
        "phone": "3c:cd:5d:a2:a9:d7"
    }
    ip_addrs = {
        "local": "192.168.1.0/24",
        "gateway": "192.168.1.1",
        "phone": "192.168.1.222"
    }


    def explicit_address(self, addr: str, type: str = "ipv4") -> str:
        """
        Return the explicit version of an IPv4 or MAC address alias.
        Example: "local" -> "192.168.0.0/16"

        :param addr: IPv4 or MAC address alias to explicit.
        :param type: Type of address (ipv4 or mac).
        :return: Explicit IPv4 or MAC address.
        :raises ValueError: If the address is not a well-known alias or an explicit address.
        """
        if addr == "self":
            # Address is "self"
            return self.device[type]
        
        # Address is not "self"

        # Get dictionary of well-known addresses, based on type
        addrs = None
        if type == "ipv4":
            addrs = self.ip_addrs
        elif type == "mac":
            addrs = self.mac_addrs
        
        if addr in addrs:
            # Address is a well-known address alias
            return addrs[addr]
        else:
            # Address is an explicit address
            return addr


    def parse(self, is_backward: bool = False, initiator: str = "src") -> dict:
        """
        Parse the ARP protocol.

        :param is_backward (optional): Whether the protocol must be parsed for a backward rule.
                                       Default is `False`.
        :param initiator (optional): Connection initiator (src or dst).
                                     Default is "src".
        :return: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Lambda function to explicit a self or a well-known MAC address
        func_mac = lambda mac: self.device['mac'] if mac == "self" else ( self.mac_addrs[mac] if mac in self.mac_addrs else mac )
        # Lambda function to explicit a self or a well-known IPv4 address
        func_ip = lambda ip: self.device['ipv4'] if ip == "self" else ( self.ip_addrs[ip] if ip in self.ip_addrs else ip )
        # Handle ARP message type
        rules = {"forward": "arp operation {}", "backward": "arp operation {}"}
        # Lambda function to flip the ARP type (for the backward rule)
        backward_func = lambda arp_type: "reply" if arp_type == "request" else ( "request" if arp_type == "reply" else arp_type )
        self.add_field("type", rules, is_backward, backward_func=backward_func)
        # Handle ARP source hardware address
        rules = {"forward": "arp saddr ether {}", "backward": "arp daddr ether {}"}
        self.add_field("sha", rules, is_backward, func_mac)
        # Handle ARP target hardware address
        rules = {"forward": "arp daddr ether {}", "backward": "arp saddr ether {}"}
        self.add_field("tha", rules, is_backward, func_mac)
        # Handle ARP source protocol address
        rules = {"forward": "arp saddr ip {}", "backward": "arp daddr ip {}"}
        self.add_field("spa", rules, is_backward, func_ip)
        # Handle ARP target protocol address
        rules = {"forward": "arp daddr ip {}", "backward": "arp saddr ip {}"}
        self.add_field("tpa", rules, is_backward, func_ip)
        return self.rules
