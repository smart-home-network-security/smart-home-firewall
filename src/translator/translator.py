"""
Translate a device YAML profile to the corresponding pair
of NFTables firewall script and NFQueue C source code.
"""

# Libraries
import os
import sys
from pathlib import Path
import argparse
import yaml
import jinja2
from typing import Tuple

# Paths
script_name = os.path.basename(__file__)
script_path = Path(os.path.abspath(__file__))
script_dir = script_path.parents[0]
sys.path.insert(0, os.path.join(script_dir, "protocols"))

# Custom classes
from LogType import LogType
from Policy import Policy
from NFQueue import NFQueue
from yaml_loaders.IncludeLoader import IncludeLoader


##### Custom Argparse types #####

def uint16(value: str) -> int:
    """
    Custom type for argparse,
    to check whether a value is an unsigned 16-bit integer,
    i.e. an integer between 0 and 65535.

    :param value: value to check
    :return: the value, if it is an unsigned 16-bit integer
    :raises argparse.ArgumentTypeError: if the value is not an unsigned 16-bit integer
    """
    result = int(value)
    if result < 0 or result > 65535:
        raise argparse.ArgumentTypeError(f"{value} is not an unsigned 16-bit integer (must be between 0 and 65535)")
    return result


##### Custom Jinja2 filters #####

def is_list(value: any) -> bool:
    """
    Custom filter for Jinja2, to check whether a value is a list.

    :param value: value to check
    :return: True if value is a list, False otherwise
    """
    return isinstance(value, list)


def debug(value: any) -> str:
    """
    Custom filter for Jinja2, to print a value.

    :param value: value to print
    :return: an empty string
    """
    print(str(value))
    return ""


##### Utility functions #####

def flatten_policies(single_policy_name: str, single_policy: dict, acc: dict = {}) -> None:
    """
    Flatten a nested single policy into a list of single policies.

    :param single_policy_name: Name of the single policy to be flattened
    :param single_policy: Single policy to be flattened
    :param acc: Accumulator for the flattened policies
    """
    if "protocols" in single_policy:
        acc[single_policy_name] = single_policy
        if single_policy.get("bidirectional", False):
            acc[f"{single_policy_name}-backward"] = single_policy
    else:
        for subpolicy in single_policy:
            flatten_policies(subpolicy, single_policy[subpolicy], acc)


def parse_policy(policy_data: dict, interaction_data: dict, global_accs: dict, policies_count: int, is_interaction: bool = False, log_type: LogType = LogType.NONE, log_group: int = 100) -> Tuple[Policy, bool]:
    """
    Parse a policy.

    :param policy_data: Dictionary containing all the necessary data to create a Policy object
    :param interaction_data: Dictionary containing the interaction data that must be updated when parsing this policy
    :param global_accs: Dictionary containing the global accumulators
    :param policies_count: Number of policies in the interaction
    :param is_interaction: Whether this policy is part of an interaction policy or not
    :param log_type: Type of packet logging to be used
    :param log_group: Log group ID to be used
    :return: the parsed policy, as a `Policy` object, and a boolean indicating whether a new NFQueue was created
    """
    # Not interaction if there is only one policy
    if policies_count == 1:
        is_interaction = False

    interaction_data["policy_idx"] += 1

    # Create and parse policy
    policy = Policy(**policy_data)
    policy.parse()

    # If the policy does not involve the device, add other device to the accumulator
    if not policy.is_device and policy.other_host:
        protocol = policy.other_host["protocol"]
        direction = policy.other_host["direction"]
        address = policy.other_host["address"]
        global_accs["other_hosts"][protocol][direction]["addrs"].add(str(address))

    # Add state(s) for this policy (if needed)
    is_first = is_interaction and interaction_data["policy_idx"] == 0
    is_last = is_interaction and interaction_data["policy_idx"] == policies_count - 1
    is_new_state = (not policy.periodic or is_first) and not (policy.transient and policy.is_backward)
    if is_new_state or (policy.periodic and is_last):
        interaction_data["max_state"] += 1
        if policy.transient:
            interaction_data["max_state"] += 1
    
    # Add nftables rules
    is_unidirectional_one_off = policy.one_off and not policy.is_bidirectional
    not_nfq = not policy.nfq_matches and not is_interaction and (policy.periodic or is_unidirectional_one_off)
    nfq_id = -1 if not_nfq else interaction_data["nfq_id_base"] + interaction_data["nfq_id_offset"]
    policy.build_nft_rule(nfq_id, log_type, log_group)
    new_nfq = False
    try:
        # Check if nft match is already stored
        nfqueue = next(nfqueue for nfqueue in global_accs["nfqueues"] if nfqueue.contains_policy_matches(policy))
    except StopIteration:
        # No nfqueue with this nft match
        nfqueue = NFQueue(f"{policy.interaction_name}#{policy.name}", policy.nft_matches, nfq_id)
        global_accs["nfqueues"].append(nfqueue)
        interaction_data["nfq_id_offset"] += 1
        new_nfq = nfq_id != -1
    finally:
        state = interaction_data["max_state"]
        is_queue_num_updated = nfqueue.add_policy(global_accs["interaction_idx"], interaction_data["policy_idx"], state, policy)
        if is_queue_num_updated:
            interaction_data["nfq_id_offset"] += 1
    
    # Add custom parser (if any)
    if policy.custom_parser:
        global_accs["custom_parsers"].add(policy.custom_parser)

    return policy, new_nfq


##### MAIN #####
if __name__ == "__main__":

    # Command line arguments
    description = "Translate a device YAML profile to the corresponding pair of NFTables firewall script and NFQueue C source code."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("profile", type=str, help="Path to the device YAML profile")
    parser.add_argument("nfq_id_base", type=uint16, help="NFQueue start index for this profile's policies (must be an integer between 0 and 65535)")
    parser.add_argument("-l", "--log-type", type=lambda log_type: LogType[log_type], choices=list(LogType), default=LogType.NONE, help="Type of packet logging to be used")
    parser.add_argument("-g", "--log-group", type=uint16, default=100, help="Log group number (must be an integer between 0 and 65535)")
    parser.add_argument("-t", "--test", action="store_true", help="Test mode: use VM instead of router")
    args = parser.parse_args()

    # Retrieve device profile's path
    device_path = os.path.abspath(os.path.dirname(args.profile))

    # Jinja2 loader
    loader = jinja2.FileSystemLoader(searchpath=f"{script_dir}/templates")
    env = jinja2.Environment(loader=loader, trim_blocks=True, lstrip_blocks=True)
    # Add custom Jinja2 filters
    env.filters["debug"] = debug
    env.filters["is_list"] = is_list
    env.filters["any"] = any
    env.filters["all"] = all

    # NFQueue ID increment
    nfq_id_inc = 10

    # Load the device profile
    with open(args.profile, "r") as f:
        
        # Load YAML profile with custom loader
        profile = yaml.load(f, IncludeLoader)

        # Get device info
        device = profile["device-info"]

        # Base nfqueue id, will be incremented at each interaction
        nfq_id_base = args.nfq_id_base

        # Global accumulators
        global_accs = {
            "interaction_idx": 0,
            "interactions": [],
            "custom_parsers": set(),
            "nfqueues": [],
            "other_hosts": {
                "arp": {
                    "src": {
                        "match": "arp saddr ip",
                        "addrs": set()
                    },
                    "dst": {
                        "match": "arp daddr ip",
                        "addrs": set()
                    }
                },
                "ipv4": {
                    "src": {
                        "match": "ip saddr",
                        "addrs": set()
                    },
                    "dst": {
                        "match": "ip daddr",
                        "addrs": set()
                    }
                },
                "ipv6": {
                    "src": {
                        "match": "ip6 saddr",
                        "addrs": set()
                    },
                    "dst": {
                        "match": "ip6 daddr",
                        "addrs": set()
                    },
                }
            }
        }
    
    
        # Loop over the device's individual policies
        if "single-policies" in profile:
            for policy_name in profile["single-policies"]:
                profile_data = profile["single-policies"][policy_name]

                policy_data = {
                    "interaction_name": "single",
                    "policy_name": policy_name,
                    "profile_data": profile_data,
                    "device": device,
                    "is_backward": False,
                    "in_interaction": False
                }
                interaction_data = {
                    "policy_idx": -1,
                    "max_state": -1,
                    "nfq_id_base": nfq_id_base,
                    "nfq_id_offset": 0,
                    "policies": []
                }
                
                # Parse policy
                is_backward = profile_data.get("bidirectional", False)
                policies_count = 2 if is_backward else 1
                policy, new_nfq = parse_policy(policy_data, interaction_data, global_accs, policies_count, False, args.log_type, args.log_group)
                interaction_data["policies"].append(policy)
                # Parse policy in backward direction, if needed
                if is_backward:
                    policy_data_backward = {
                        "interaction_name": "single",
                        "policy_name": f"{policy_name}-backward",
                        "profile_data": profile_data,
                        "device": device,
                        "is_backward": True,
                        "in_interaction": False
                    }
                    policy_backward, new_nfq = parse_policy(policy_data_backward, interaction_data, global_accs, policies_count, False, args.log_type, args.log_group)
                    interaction_data["policies"].append(policy_backward)

                # Update nfqueue variables if needed
                if new_nfq:
                    nfq_id_base += nfq_id_inc

                global_accs["interactions"].append(interaction_data)
                global_accs["interaction_idx"] += 1


        # Loop over the device's interaction policies
        if "interactions" in profile:
            for interaction_policy_name in profile["interactions"]:
                interaction_policy = profile["interactions"][interaction_policy_name]

                # Iterate on single policies

                # First pass, to flatten nested policies
                single_policies = {}
                for single_policy_name in interaction_policy:
                    flatten_policies(single_policy_name, interaction_policy[single_policy_name], single_policies)

                # Second pass, parse policies
                interaction_data = {
                    "policy_idx": -1,
                    "max_state": -1,
                    "nfq_id_base": nfq_id_base,
                    "nfq_id_offset": 0,
                    "policies": []
                }

                update_nfq_id_base = False
                for single_policy_name in single_policies:
                    # Create policy and parse it
                    profile_data = single_policies[single_policy_name]
                    try:
                        timeout = profile_data["timeout"]
                    except KeyError:
                        timeout = 0
                    is_backward = "backward" in single_policy_name and profile_data.get("bidirectional", False)
                    policy_data = {
                        "interaction_name": interaction_policy_name,
                        "policy_name": single_policy_name,
                        "profile_data": profile_data,
                        "device": device,
                        "is_backward": is_backward,
                        "in_interaction": True,
                        "timeout": timeout
                    }
                    single_policy, new_nfq = parse_policy(policy_data, interaction_data, global_accs, len(single_policies), True, args.log_type, args.log_group)
                    if new_nfq:
                        update_nfq_id_base = True
                    interaction_data["policies"].append(single_policy)

                # Update nfqueue variables
                global_accs["interactions"].append(interaction_data)
                global_accs["interaction_idx"] += 1
                if update_nfq_id_base:
                    nfq_id_base += nfq_id_inc

        # Create nfqueue C file by rendering Jinja2 templates
        header_dict = {
            "device": device["name"],
            "custom_parsers": global_accs["custom_parsers"],
            "num_threads": len(global_accs["nfqueues"]),
            "interactions": global_accs["interactions"]
        }
        header = env.get_template("header.c.j2").render(header_dict)
        callback_dict = {
            "nft_table": f"bridge {device['name']}",
            "interactions": global_accs["interactions"],
            "nfqueues": global_accs["nfqueues"]
        }
        callback = env.get_template("callback.c.j2").render(callback_dict)
        main_dict = {
            "interactions": global_accs["interactions"],
            "custom_parsers": global_accs["custom_parsers"],
            "nfqueues": global_accs["nfqueues"]
        }
        main = env.get_template("main.c.j2").render(main_dict)

        # Write policy C file
        with open(f"{device_path}/nfqueues.c", "w+") as fw:
            fw.write(header)
            fw.write(callback)
            fw.write(main)

        # Create nftables script
        nft_dict = {
            "device": device,
            "other_hosts": global_accs["other_hosts"],
            "nfqueues": global_accs["nfqueues"],
            "log_type": args.log_type,
            "log_group": args.log_group,
            "test": args.test
        }
        env.get_template("firewall.nft.j2").stream(nft_dict).dump(f"{device_path}/firewall.nft")

        # Create CMake file
        cmake_dict = {"device": device["name"]}
        env.get_template("CMakeLists.txt.j2").stream(cmake_dict).dump(f"{device_path}/CMakeLists.txt")

    print(f"Done translating {args.profile}.")
