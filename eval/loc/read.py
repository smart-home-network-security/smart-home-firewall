#!/usr/bin/python3

import os
from pathlib import Path
import csv
import yaml


### GLOBAL VARIABLES ###

script_name = os.path.basename(__file__)
script_path = Path(os.path.abspath(__file__))
script_dir = script_path.parents[0]
base_dir = script_path.parents[2]
devices = [
    "dlink-cam",
    "philips-hue",
    "smartthings-hub",
    "tplink-plug",
    "xiaomi-cam"
]


### FUNCTIONS ###

def get_num_policies_in_interaction(interaction: dict) -> int:
    """
    Retrieve the number of policies in an interaction.

    :param interaction: interaction to parse
    :return: number of policies in the interaction
    """
    num_policies = 0
    for k, v in interaction.items():
        if isinstance(v, dict):
            if "protocols" in v.keys():
                num_policies += 1
                if v.get("bidirectional", False):
                    num_policies += 1
            else:
                num_policies += get_num_policies_in_interaction(v)
        elif isinstance(v, list):
            for item in v:
                num_policies += get_num_policies_in_interaction(item)
    return num_policies


### MAIN ###

if __name__ == "__main__":

    result_file_name = os.path.join(script_dir, "data.csv")
    with open(result_file_name, "w") as result_file:
        fieldnames = ["device", "num_interactions", "num_policies", "nft_rules", "nfq_loc"]
        writer = csv.DictWriter(result_file, fieldnames=fieldnames)
        writer.writeheader()

        # Iterate on devices
        for device in devices:

            # Device directory
            device_path = os.path.join(base_dir, "devices", device)
            
            # Read device's expanded profile
            expanded_profile_path = os.path.join(device_path, "expanded_profile.yaml")
            with open(expanded_profile_path, "r") as profile_file:
                profile = yaml.safe_load(profile_file)

                # Read policies and interactions
                single_policies = profile.get("single-policies", [])
                interactions = profile.get("interactions", [])


                ### NUMBER OF INTERACTIONS ###

                num_interactions = len(single_policies) + len(interactions)


                ### NUMBER OF POLICIES ###

                num_policies = 0
                
                # Iterate on single policies
                # + 1 if policy is unidirectional
                # + 2 if policy is bidirectional
                for _, single_policy in single_policies.items():
                    num_policies += 1
                    if single_policy.get("bidirectional", False):
                        num_policies += 1
                
                # Iterate on interactions
                # + 1 per policy in interactions
                # + 2 if policy is bidirectional
                for _, interaction in interactions.items():
                    num_policies += get_num_policies_in_interaction(interaction)

                
                ### NUMBER OF NFTABLES RULES ###

                num_rules = 0
                # Get device nftables script
                nft_script_path = os.path.join(device_path, "firewall.nft")
                with open(nft_script_path, "r") as nft_script:
                    nft_script_content = nft_script.read()

                    # Count number of rules
                    num_rules += nft_script_content.count("queue num")
                    num_rules += nft_script_content.count("accept")
                    num_rules -= 2  # Remove the default policy and ACCEPT rule


                ### LINES OF NFQUEUE CODE ###

                nfq_loc = 0
                # Get device NFQueue source code
                nfq_src_path = os.path.join(device_path, "nfqueues.c")
                with open(nfq_src_path, "r") as nfq_src:
                    # Count number of lines
                    for count, line in enumerate(nfq_src):
                        pass
                    num_loc = count + 1

                row = {
                    "device": device,
                    "num_interactions": num_interactions,
                    "num_policies": num_policies,
                    "nft_rules": num_rules,
                    "nfq_loc": num_loc
                }
                writer.writerow(row)
