import re
from copy import deepcopy
from LogType import LogType
from Policy import Policy

class NFQueue:
    """
    Class which represents a single nfqueue.
    """

    # Class variables
    time_units = {
        "second": 1,
        "minute": 60,
        "hour":   60 * 60,
        "day":    60 * 60 * 24,
        "week":   60 * 60 * 24 * 7
    }


    def __init__(self, name: str, nft_matches: list, queue_num: int = -1) -> None:
        """
        Initialize a new NFQueue object.

        :param name: descriptive name for the nfqueue
        :param nft_matches: list of nftables matches corresponding to this queue
        :param queue_num: number of the nfqueue queue corresponding to this policy,
                          or a negative number if the policy is simply `accept`
        """
        self.name = name            # Descriptive name for this nfqueue (name of the first policy to be added)
        self.queue_num = queue_num  # Number of the corresponding nfqueue
        self.policies = []          # List of policies associated to this nfqueue
        self.nft_matches = deepcopy(nft_matches)  # List of nftables matches associated to this nfqueue
        self.nft_stats = {}
    

    def __eq__(self, other: object) -> bool:
        """
        Compare another object to this NFQueue object.

        :param other: object to compare to this NFQueue object
        :return: True if the other object is an NFQueue object with the same nftables match, False otherwise
        """
        if not isinstance(other, self.__class__):
            return NotImplemented
        key_func = lambda x: x["template"].format(x["match"])
        self_matches = sorted(self.nft_matches, key=key_func)
        other_matches = sorted(other.nft_matches, key=key_func)
        return ( self.name == other.name and
                 self.queue_num == other.queue_num and
                 self_matches == other_matches )

    
    def contains_policy_matches(self, policy: Policy) -> bool:
        """
        Check if this NFQueue object contains the nftables matches of the given policy.

        :param policy: policy to check
        :return: True if this NFQueue object contains the nftables matches of the given policy, False otherwise
        """
        key_func = lambda x: x["template"].format(x["match"])
        policy_matches = sorted(policy.nft_matches, key=key_func)
        self_matches = sorted(self.nft_matches, key=key_func)
        return policy_matches == self_matches
    

    @staticmethod
    def parse_rate_match(match: str) -> dict:
        """
        Parse the rate match and return a dictionary containing the rate and burst values.

        :param match: rate match to parse
        :return: dictionary containing the rate and burst values, or None if the match could not be parsed
        """
        # Try to match a rate of 0, which means no rate limit
        if match == 0:
            return {"value": 0, "unit": None}
        
        # Try to match a packet rate with burst
        try:
            return re.compile(r"\s*(?P<value>\d+)/(?P<unit>second|minute|hour|day|week)\s+burst\s+(?P<burst_value>\d+)\s+(?P<burst_unit>packets|.bytes)\s*").match(match).groupdict()
        except AttributeError:
            pass

        # Try to match a packet rate without burst
        try:
            return re.compile(r"\s*(?P<value>\d+)/(?P<unit>second|minute|hour|day|week)\s*").match(match).groupdict()
        except AttributeError:
            pass
        
        # Return None if the match could not be parsed
        return None


    def update_rate_match(self, new_match: str) -> None:
        """
        Update the rate NFTables match for this NFQueue object, if needed.

        :param new_match: new match to be compared to the current one
        """
        old_match = NFQueue.parse_rate_match(self.nft_stats["rate"]["match"])
        new_match = NFQueue.parse_rate_match(new_match)

        # One of the rates is 0, which means no rate limit
        if old_match["value"] == 0 or new_match["value"] == 0:
            self.nft_stats["rate"]["match"] = 0
            return

        # Both rates are specified
        # Compute and update rate
        old_rate = float(old_match["value"]) / NFQueue.time_units[old_match["unit"]]
        new_rate = float(new_match["value"]) / NFQueue.time_units[new_match["unit"]]
        rate_sum = int(old_rate + new_rate)
        updated_rate = "{}/{}".format(rate_sum, "second")

        # Compute and update new burst, if needed
        if "burst_value" in old_match and "burst_value" in new_match:
            if old_match["burst_unit"] == new_match["burst_unit"]:
                old_burst = int(old_match["burst_value"])
                new_burst = int(new_match["burst_value"])
                burst_sum = old_burst + new_burst
                updated_rate += " burst {} {}".format(burst_sum, old_match["burst_unit"])
            else:
                # Burst units are different, so we cannot sum them
                # Keep the old burst
                updated_rate += " burst {} {}".format(old_match["burst_value"], old_match["burst_unit"])
        elif "burst_value" in new_match:
            updated_rate += " burst {} {}".format(new_match["burst_value"], new_match["burst_unit"])
        elif "burst_value" in old_match:
            updated_rate += " burst {} {}".format(old_match["burst_value"], old_match["burst_unit"])

        # Set updated rate
        self.nft_stats["rate"]["match"] = updated_rate    
    

    @staticmethod
    def parse_size_match(match: str) -> tuple:
        """
        Parse the packet size match and return a tuple containing the lower and upper bounds.

        :param match: packet size match to parse
        :return: tuple containing the lower and upper bounds of the packet size match,
                 or None if the match could not be parsed
        """
        try:
            # Try to match a single upper bound value
            re_upper = int(re.compile(r"\s*<\s*(?P<upper>\d+)\s*").match(match).group("upper"))
            re_lower = 0
        except AttributeError:
            try:
                # Try to match a range of values
                re_range = re.compile(r"\s*(?P<lower>\d+)\s*-\s*(?P<upper>\d+)\s*").match(match)
                re_lower = int(re_range.group("lower"))
                re_upper = int(re_range.group("upper"))
            except AttributeError:
                # No match found
                return None
        return (re_lower, re_upper)

    
    def update_size_match(self, new_match: str):
        """
        Update the packet size NFTables match for this NFQueue object, if needed.

        :param new_match: new match to be compared to the current one
        """
        old_values = NFQueue.parse_size_match(self.nft_stats["packet-size"]["match"])
        new_values = NFQueue.parse_size_match(new_match)
        new_lower = min(old_values[0], new_values[0])
        new_upper = max(old_values[1], new_values[1])
        if new_lower == 0:
            new_match = "< {}".format(new_upper)
        else:
            new_match = "{} - {}".format(new_lower, new_upper)
        self.nft_stats["packet-size"]["match"] = new_match
    

    def update_match(self, stat: str, new_match: str):
        """
        Update the match for the given stat, if needed.
        Stat match is set to the least restrictive match between the current and the new one.
        
        :param stat: name of the stat to update
        :param new_match: new match to set, if needed
        """
        if stat == "rate":
            self.update_rate_match(new_match)
        elif stat == "packet-size":
            self.update_size_match(new_match)


    def add_policy(self, interaction_idx: int, policy_idx: int, state: int, policy: Policy) -> bool:
        """
        Add a policy to this NFQueue object.

        :param interaction_idx: index of the interaction for which the policy must be added
        :param policy_idx: index of the policy inside the interaction
        :param state: state for which the policy must be added
        :param policy: policy to add
        :param timeout: the timeout of the policy
        :return: True if the nfqueue queue number has been updated, False otherwise
        """
        result = False
        timeout = policy.timeout
        # Update nfqueue queue number if necessary
        if self.queue_num < 0 and policy.queue_num >= 0:
            self.queue_num = policy.queue_num
            result = True

        # Create policy dictionary
        policy_dict = {
            "interaction_idx": interaction_idx,
            "policy_idx": policy_idx,
            "state": state,
            "policy": policy,
            "counters_idx": {},
            "timeout": timeout
        }

        # Update NFT stat matches if necessary
        nfq_stats = policy.get_nft_match_stats()
        for stat, data in nfq_stats.items():
            if stat not in self.nft_stats:
                self.nft_stats[stat] = data
            else:
                self.update_match(stat, data["match"])

        # Add counter info
        for counter in [counter for counter in Policy.stats_metadata if Policy.stats_metadata[counter].get("counter", False)]:
            if policy.is_base_for_counter(counter):
                policy_dict["counters_idx"][counter] = policy_idx
            elif policy.is_backward_for_counter(counter):
                policy_dict["counters_idx"][counter] = policy_idx - 1

        # Append policy to the list of policies
        self.policies.append(policy_dict)
        # Sort list of policies, with default accept policies at the end
        sort_key = lambda x: (x["policy"])
        self.policies.sort(key=sort_key)
        return result


    def get_nft_rule(self, log_type: LogType = LogType.NONE, log_group: int = 100) -> str:
        """
        Retrieve the complete nftables rule, composed of the complete nftables match
        and the action, for this nfqueue.

        :return: complete nftables rule for this nfqueue
        """
        nft_rule = ""
        for nft_match in self.nft_matches:
            nft_rule += nft_match["template"].format(nft_match["match"]) + " "
        for stat in self.nft_stats.values():
            if stat["match"] != 0:
                nft_rule += stat["template"].format(stat["match"]) + " "
        nft_action = f"queue num {self.queue_num}" if self.queue_num >= 0 else "accept"
        verdict = "ACCEPT" if "accept" in nft_action else "QUEUE"
        if log_type == LogType.CSV:
            log = f"log prefix \"{self.name},,{verdict}\" group {log_group}"
            return f"{nft_rule}{log} {nft_action}"
        elif log_type == LogType.PCAP:
            log = f"log group {log_group}"
            return f"{nft_rule}{log} {nft_action}"
        else:
            return f"{nft_rule}{nft_action}"
