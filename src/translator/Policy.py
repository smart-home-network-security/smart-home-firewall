from enum import Enum
from typing import Tuple, Dict
from math import ceil
import ipaddress
from protocols.Protocol import Protocol
from protocols.ip import ip
from LogType import LogType


class Policy:
    """
    Class which represents a single access control policy.
    """

    class NftType(Enum):
        """
        Enum: NFTables types.
        Possible values:
            - MATCH: nftables match
            - ACTION: nftables action
        """
        MATCH = 1
        ACTION = 2

    # Metadata for supported nftables statistics
    stats_metadata = {
        "rate": {"nft_type": NftType.MATCH, "counter": False, "template": "limit rate {}"},
        "packet-size": {"nft_type": NftType.MATCH, "counter": False, "template": "ip length {}"},
        "packet-count": {"counter": True},
        "duration": {"counter": True}
    }

    def __init__(self, interaction_name: str, policy_name: str, profile_data: dict, device: dict, is_backward: bool = False, in_interaction: bool = False, timeout = 0, activity_period: dict = None) -> None:
        """
        Initialize a new Policy object.

        :param name: Name of the policy
        :param profile_data: Dictionary containing the policy data from the YAML profile
        :param device: Dictionary containing the device metadata from the YAML profile
        :param is_backward: Whether the policy is backwards (i.e. the source and destination are reversed)
        :param in_interaction: Whether the policy is part of an interaction
        :param logging: Whether to enable logging
        """
        self.interaction_name = interaction_name  # Name of the interaction this policy belongs to
        self.name = policy_name                   # Policy name
        self.profile_data = profile_data          # Policy data from the YAML profile
        self.is_backward = is_backward            # Whether the policy is backwards (i.e. the source and destination are reversed)
        self.in_interaction = in_interaction      # Whether the policy is part of an interaction
        self.device = device                      # Dictionary containing data for the device this policy is linked to
        self.custom_parser = ""                   # Name of the custom parser (if any)
        self.nft_matches = []                     # List of nftables matches (will be populated by parsing)
        self.nft_stats = {}                       # Dict of nftables statistics (will be populated by parsing)
        self.nft_match = ""                       # Complete nftables match (including rate and packet size)
        self.queue_num = -1                       # Number of the nfqueue queue corresponding (will be updated by parsing)
        self.nft_action = ""                      # nftables action associated to this policy
        self.nfq_matches = []                     # List of nfqueue matches (will be populated by parsing)
        self.counters = {}                        # Counters associated to this policy (will be populated by parsing)
        self.is_device = False                    # Whether the policy involves the device
        self.other_host = {}                      # If the policy does not involve the device, this will be set to the IP address of the other local involved device
        self.timeout = timeout
        self.activity_period = activity_period

        self.is_bidirectional = self.profile_data.get("bidirectional", False)  # Whether the policy is bidirectional
        self.transient = self.is_transient()  # Whether the policy represents a transient pattern
        self.periodic = self.is_periodic()    # Whether the policy represents a periodic pattern
        self.one_off = not self.transient and not self.periodic  # Whether the policy represents a one-off pattern
        self.initiator = profile_data["initiator"] if "initiator" in profile_data else ""

        # Newly added: Add new loop-related attributes
        self.is_loop_policy = False     # Whether this policy is part of a loop
        self.loop_role = ""             # Role in terms of loop: "enter", "next", or ""

    def __eq__(self, other: object) -> bool:
        """
        Check whether this Policy object is equal to another object.

        :param other: object to compare to this Policy object
        :return: True if the other object represents the same policy, False otherwise
        """
        if not isinstance(other, self.__class__):
            return NotImplemented
        # Other object is a Policy object
        key_func = lambda x: x["template"].format(x["match"])
        self_matches = sorted(self.nft_matches, key=key_func)
        other_matches = sorted(other.nft_matches, key=key_func)
        return ( other.name == self.name and
                 other.is_backward == self.is_backward and
                 self.in_interaction == other.in_interaction and
                 self.device == other.device and
                 self_matches == other_matches and
                 self.nft_stats == other.nft_stats and
                 self.nft_action == other.nft_action and
                 self.queue_num == other.queue_num and
                 self.is_bidirectional == other.is_bidirectional and
                 self.transient == other.transient and
                 self.periodic == other.periodic and
                 # Newly added: Add new loop-related attribute comparisons
                 self.is_loop_policy == other.is_loop_policy and
                 self.loop_role == other.loop_role)
                


    def __lt__(self, other: object) -> bool:
        """
        Check whether this Policy object is less than another object.

        :param other: object to compare to this Policy object
        :return: True if this Policy object is less than the other object, False otherwise
        """
        if not isinstance(other, self.__class__):
            return NotImplemented
        # Other object is a Policy object
        if self.queue_num >= 0 and other.queue_num >= 0:
            return self.queue_num < other.queue_num
        elif self.queue_num < 0:
            return False
        elif other.queue_num < 0:
            return True
        else:
            return self.name < other.name


    def __hash__(self) -> int:
        """
        Compute a hash value for this Policy object.

        :return: hash value for this Policy object
        """
        return hash((self.name, self.is_backward))

    
    def is_transient(self) -> bool:
        """
        Check whether the policy represents a transient pattern.

        :return: True if this policy represents a transient pattern, False otherwise
        """
        return "stats" in self.profile_data and ("duration" in self.profile_data["stats"] or "packet-count" in self.profile_data["stats"])


    def is_periodic(self) -> bool:
        """
        Check whether the policy represents a periodic pattern.

        :return: True if this policy represents a periodic pattern, False otherwise
        """
        return "stats" in self.profile_data and "rate" in self.profile_data["stats"] and ("duration" not in self.profile_data["stats"] and "packet-count" not in self.profile_data["stats"])


    @staticmethod
    def get_field_static(var: any, field: str, parent_key: str = "") -> Tuple[any, any]:
        """
        Retrieve the parent key and value for a given field in a dict.
        Adapted from https://stackoverflow.com/questions/9807634/find-all-occurrences-of-a-key-in-nested-dictionaries-and-lists.

        :param var: Data structure to search in
        :param field: Field to retrieve
        :param parent_key: Parent key of the current data structure
        :return: tuple containing the parent key and the value for the given field,
                 or None if the field is not found
        """
        if hasattr(var, 'items'):
            for k, v in var.items():
                if k == field:
                    return parent_key, v
                if isinstance(v, dict):
                    result = Policy.get_field_static(v, field, k)
                    if result is not None:
                        return result
                elif isinstance(v, list):
                    for d in v:
                        result = Policy.get_field_static(d, field, k)
                        if result is not None:
                            return result
        return None
    

    def get_field(self, field: str) -> Tuple[any, any]:
        """
        Retrieve the value for a given field in the policy profile data.
        Adapted from https://stackoverflow.com/questions/9807634/find-all-occurrences-of-a-key-in-nested-dictionaries-and-lists.

        :param field: Field to retrieve
        :return: tuple containing the parent key and the value for the given field,
                 or None if the field is not found
        """
        return Policy.get_field_static(self.profile_data, field, self.name)
    

    @staticmethod
    def parse_duration(duration: str) -> int:
        """
        Parse the duration statistic value, and convert it to microseconds.
        This value has the form "<value> <unit>".
        
        :param duration: Duration value to parse
        :return: duration value in microseconds
        :raises ValueError: if the duration unit is invalid (not in the list of supported units, i.e. seconds, milliseconds, or microseconds)
        """
        # Time units {multiplier: [aliases]}
        time_units = {
            1_000_000: ["s", "sec", "secs", "second", "seconds"],
            1_000: ["ms", "msec", "msecs", "millisecond", "milliseconds"],
            1: ["us", "usec", "usecs", "microsecond", "microseconds"]
        }

        # Parse duration value
        duration_split = str(duration).strip().split()
        value = duration_split[0]
        # Convert value to float
        try:
            value = float(value)
        except ValueError:
            raise ValueError("Invalid duration value: {}".format(value))
        
        # Parse duration unit
        unit = ""
        if len(duration_split) < 2 or not duration_split[1]:
            # No unit specified, assume seconds
            unit = "s"
        else:
            # Unit specified
            unit = duration_split[1]

        # Iterate over time units
        for mult, aliases in time_units.items():
            if unit in aliases:
                # Convert value to microseconds and round to upper integer
                return ceil(value * mult)
        
        # Finished iteration, invalid unit
        raise ValueError("Invalid duration unit: {}".format(unit))

    
    def parse_stat(self, stat: str) -> Dict[str, str]:
        """
        Parse a single statistic.
        Add the corresponding counters and nftables matches.

        :param stat: Statistic to handle
        :return: parsed stat, with the form {"template": ..., "match": ...}
        """
        parsed_stat = None
        value = self.profile_data["stats"][stat]
        if type(value) == dict:
            # Stat is a dictionary, and contains data for directions "fwd" and "bwd"
            value_fwd = Policy.parse_duration(value["fwd"]) if stat == "duration" else value["fwd"]
            value_bwd = Policy.parse_duration(value["bwd"]) if stat == "duration" else value["bwd"]
            if Policy.stats_metadata[stat]["counter"]:
                # Add counters for "fwd" and "bwd" directions
                self.counters[stat] = {
                    "fwd": value_fwd,
                    "bwd": value_bwd
                }
            if stat in Policy.stats_metadata and "template" in Policy.stats_metadata[stat]:
                parsed_stat = {
                    "template": Policy.stats_metadata[stat]["template"],
                    "match": value_bwd if self.is_backward else value_fwd,
                }
        else:
            # Stat is a single value, which is used for both directions
            if Policy.stats_metadata[stat]["counter"]:
                value = Policy.parse_duration(value) if stat == "duration" else value
                self.counters[stat] = {"default": value}
                value = f"\"{self.name[:-len('-backward')] if self.is_backward else self.name}\""
            if stat in Policy.stats_metadata and "template" in Policy.stats_metadata[stat]:
                parsed_stat = {
                    "template": Policy.stats_metadata[stat]["template"],
                    "match": value
                }
        
        if parsed_stat is not None and "nft_type" in Policy.stats_metadata[stat]:
            self.nft_stats[stat] = parsed_stat

    
    def build_nft_rule(self, queue_num: int, log_type: LogType = LogType.NONE, log_group: int = 100) -> str:
        """
        Build and store the nftables match and action, as strings, for this policy.

        :param queue_num: number of the nfqueue queue corresponding to this policy,
                          or a negative number if the policy is simply `accept`
        :param log_type: type of logging to enable
        :param log_group: log group number
        :return: complete nftables rule for this policy
        """
        self.queue_num = queue_num

        # nftables match
        for i in range(len(self.nft_matches)):
            if i > 0:
                self.nft_match += " "
            template = self.nft_matches[i]["template"]
            data = self.nft_matches[i]["match"]
            self.nft_match += template.format(*(data)) if type(data) == list else template.format(data)
        
        # nftables stats
        for stat in self.nft_stats:
            template = self.nft_stats[stat]["template"]
            data = self.nft_stats[stat]["match"]
            if Policy.stats_metadata[stat].get("nft_type", 0) == Policy.NftType.MATCH:
                self.nft_match += " " + (template.format(*(data)) if type(data) == list else template.format(data))
            elif Policy.stats_metadata[stat].get("nft_type", 0) == Policy.NftType.ACTION:
                if self.nft_action:
                    self.nft_action += " "
                self.nft_action += (template.format(*(data)) if type(data) == list else template.format(data))

        ## nftables action
        if self.nft_action:
            self.nft_action += " "
        verdict = "QUEUE" if queue_num >= 0 else "ACCEPT"
        # Log action
        if log_type == LogType.CSV:
            self.nft_action += f"log prefix \\\"{self.interaction_name}#{self.name},,{verdict}\\\" group {log_group} "
        elif log_type == LogType.PCAP:
            self.nft_action += f"log group {log_group} "
        # Verdict action
        self.nft_action += f"queue num {queue_num}" if queue_num >= 0 else "accept"

        return self.get_nft_rule()

    
    def get_nft_rule(self) -> str:
        """
        Retrieve the complete nftables rule, composed of the complete nftables match
        and the action, for this policy.

        :return: complete nftables rule for this policy
        """
        return f"{self.nft_match} {self.nft_action}"

    
    def parse(self) -> None:
        """
        Parse the policy and populate the related instance variables.
        """
        # Parse protocols
        for protocol_name in self.profile_data["protocols"]:
            try:
                profile_protocol = self.profile_data["protocols"][protocol_name]
                protocol = Protocol.init_protocol(protocol_name, profile_protocol, self.device)
            except ModuleNotFoundError:
                # Unsupported protocol, skip it
                continue
            else:
                # Protocol is supported, parse it

                # Add custom parser if needed
                if protocol.custom_parser:
                    self.custom_parser = protocol_name
                
                ### Check involved devices
                protocols = ["arp", "ipv4", "ipv6"]
                # This device's addresses
                addrs = ["mac", "ipv4", "ipv6"]
                self_addrs = ["self"]
                for addr in addrs:
                    device_addr = self.device.get(addr, None)
                    if device_addr is not None:
                        self_addrs.append(device_addr)
                if protocol_name in protocols:
                    ip_proto = "ipv6" if protocol_name == "ipv6" else "ipv4"
                    src = profile_protocol.get("spa", None) if protocol_name == "arp" else profile_protocol.get("src", None)
                    dst = profile_protocol.get("tpa", None) if protocol_name == "arp" else profile_protocol.get("dst", None)
                    
                    # Check if device is involved
                    if src in self_addrs or dst in self_addrs:
                        self.is_device = True
                    
                    # Device is not involved
                    else:
                        # Try expliciting source address
                        try:
                            saddr = ipaddress.ip_network(protocol.explicit_address(src))
                        except ValueError:
                            saddr = None
                        
                        # Try expliciting destination address
                        try:
                            daddr = ipaddress.ip_network(protocol.explicit_address(dst))
                        except ValueError:
                            daddr = None

                        # Check if the involved other host is in the local network
                        local_networks = ip.addrs[ip_proto]["local"]
                        if isinstance(local_networks, list):
                            lans = map(lambda cidr: ipaddress.ip_network(cidr), local_networks)
                        else:
                            lans = [ipaddress.ip_network(local_networks)]
                        if saddr is not None and any(lan.supernet_of(saddr) for lan in lans):
                            self.other_host["protocol"] = protocol_name
                            self.other_host["direction"] = "src"
                            self.other_host["address"] = saddr
                        elif daddr is not None and any(lan.supernet_of(daddr) for lan in lans):
                            self.other_host["protocol"] = protocol_name
                            self.other_host["direction"] = "dst"
                            self.other_host["address"] = daddr

                # Add nft rules
                new_rules = protocol.parse(is_backward=self.is_backward, initiator=self.initiator)
                self.nft_matches += new_rules["nft"]

                # Add nfqueue matches
                for match in new_rules["nfq"]:
                    self.nfq_matches.append(match)
        
        # Parse statistics
        if "stats" in self.profile_data:
            for stat in self.profile_data["stats"]:
                if stat in Policy.stats_metadata:
                    self.parse_stat(stat)

    
    def get_domain_name_hosts(self) -> Tuple[str, dict]:
        """
        Retrieve the domain names and IP addresses for this policy, if any.

        :return: tuple containing:
                    - the IP family nftables match (`ip` or `ip6`)
                    - a dictionary containing a mapping between the direction matches (`saddr` or `daddr`)
                      and the corresponding domain names or ip addresses
        """
        result = {}
        directions = {
            "src": "daddr" if self.is_backward else "saddr",
            "dst": "saddr" if self.is_backward else "daddr"
        }
        protocol = "ipv4"
        for dir, match in directions.items():
            field = self.get_field(dir)
            if field is None:
                # Field is not present in the policy
                continue

            protocol, addr = self.get_field(dir)
            if not ip.is_ip_static(addr, protocol):
                # Host is a domain name, or
                # list of hosts includes domain names
                if type(addr) is list:
                    # Field is a list of hosts
                    for host in addr:
                        if ip.is_ip_static(host, protocol):
                            # Host is an explicit or well-known address
                            if match not in result:
                                result[match] = {}
                            result[match]["ip_addresses"] = result[match].get("ip_addresses", []) + [host]
                        else:
                            # Address is not explicit or well-known, might be a domain name
                            if match not in result:
                                result[match] = {}
                            result[match]["domain_names"] = result[match].get("domain_names", []) + [host]
                else:
                    # Field is a single host
                    if match not in result:
                        result[match] = {}
                    result[match]["domain_names"] = result[match].get("domain_names", []) + [addr]
        protocol = "ip" if protocol == "ipv4" else "ip6"
        return protocol, result


    def is_base_for_counter(self, counter: str):
        """
        Check if the policy is the base policy for a given counter.

        :param counter: Counter to check (packet-count or duration)
        :return: True if the policy is the base policy for the given counter and direction, False otherwise
        """
        if counter not in self.counters:
            return False

        # Counter is present for this policy
        direction = "bwd" if self.is_backward else "fwd"
        return ( ("default" in self.counters[counter] and not self.is_backward) or
                  direction in self.counters[counter] )
    

    def is_backward_for_counter(self, counter: str):
        """
        Check if the policy is the backward policy for a given counter.

        :param counter: Counter to check (packet-count or duration)
        :return: True if the policy is the backward policy for the given counter and direction, False otherwise
        """
        if counter not in self.counters:
            return False
        
        # Counter is present for this policy
        return "default" in self.counters[counter] and self.is_backward
    

    def get_data_from_nfqueues(self, nfqueues: list) -> dict:
        """
        Retrieve the policy dictionary from the nfqueue list.

        :param nfqueues: List of nfqueues
        :return: dictionary containing the policy data,
                 or None if the policy is not found
        """
        for nfqueue in nfqueues:
            for policy_dict in nfqueue.policies:
                if policy_dict["policy"] == self:
                    return policy_dict
        return None
    

    def get_nft_match_stats(self) -> dict:
        """
        Retrieve this policy's stats which correspond to an NFTables match.

        :return: dictionary containing the policy match statistics
        """
        result = {}
        for stat, data in self.nft_stats.items():
            if Policy.stats_metadata.get(stat, {}).get("nft_type", None) == Policy.NftType.MATCH:
                result[stat] = data
        return result
