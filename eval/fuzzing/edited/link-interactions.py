#!/usr/bin/python3

"""
Link recorded packet verdicts with corresponding device interactions.
Indicate, for each packet, if it should have been accepted or dropped.
"""

## Import libraries
import os
from pathlib import Path
import json
import csv
import yaml
import logging
# Import custom PyYAML loader
from pyyaml_loaders import IncludeLoader

# Verdict values
ACCEPT = "ACCEPT"
DROP = "DROP"
QUEUE = "QUEUE"

# DNS RR types
DNS_RR_TYPES = {
    1:   "A",
    2:   "NS",
    3:   "MD",
    4:   "MF",
    5:   "CNAME",
    6:   "SOA",
    7:   "MB",
    8:   "MG",
    9:   "MR",
    10:  "NULL",
    11:  "WKS",
    12:  "PTR",
    13:  "HINFO",
    14:  "MINFO",
    15:  "MX",
    16:  "TXT",
    28:  "AAAA",
    41:  "OPT",
    255: "ANY"
}


def get_packets_by_timestamp(packet_list: list, packet_timestamp: any) -> list:
    """
    Retrieve a list of packets with the given timestamp from the given packet list,
    or return an empty list if no such packet exists.

    :param packet_list: List of packets.
    :param packet_timestamp: Packet timestamp to search for.
    :return: List of packets with the given timestamp.
    """
    packet_timestamp = float(packet_timestamp)
    return [packet for packet in packet_list if float(packet["timestamp"]) == packet_timestamp]


def get_packets_by_id(packet_list: list, packet_ids: list) -> list:
    """
    Get the packets with the given IDs from the given packet list,
    or return an empty list

    :param packet_list: List of packets to search in.
    :param packet_ids: Packet IDs to search for.
    :return: List of packets with the given IDs.
    """
    return [packet for packet in packet_list if int(packet["id"]) in packet_ids]


def get_packet_by_id(packet_list: list, packet_id: any) -> bool:
    """
    Get the packets with the given IDs from the given packet list,
    or return None if no such packet exists.

    :param packet_list: List of packets.
    :param packet_id: Packet ID to search for.
    :return: Packet with the given ID, or None if no such packet exists.
    """
    packet_id = int(packet_id)
    return next((packet for packet in packet_list if int(packet["id"]) == packet_id), None)
    

def is_default_drop(policy: str) -> bool:
    """
    Check if the given policy is the default drop policy.

    :param policy: Policy to check.
    :return: True if the policy is the default drop policy, False otherwise.
    """
    return len(policy.split("#")) == 1


def is_same_interaction(previous_policy: str, current_policy: str) -> bool:
    """
    Check if the previous policy is in the same interaction as the current one.

    :param previous_policy: Previous policy.
    :param current_policy: Current policy.
    :return: True if the previous policy is in the same interaction as the current one
             or if the previous interaction is empty,
             False otherwise.
    """
    split = previous_policy.split("#")
    current_interaction, current_policy = current_policy.split("#")
    # Handle single policies, forward and backward
    is_same_single = (split[0] == "single" and (split[1] in current_policy or current_policy in split[1]))
    return ( split[0] == current_interaction or  # Same interaction
             is_same_single )                    # Same single policy


def is_same_policy(policy_a: str, policy_b: str) -> bool:
    """
    Check if the given policies are the same.

    :param policy_a: First policy.
    :param policy_b: Second policy.
    :return: True if the policies are the same, False otherwise.
    """
    return policy_a in policy_b or policy_b in policy_a


def deep_get(d: dict, key: str, top_key: str = None) -> any:
    """
    Retrieve the value corresponding to the given key in the given nested dictionary.

    :param d: Nested dictionary to search in.
    :param key: Key to search for.
    :param top_key: If specified, top-level key to search in.
    :return: Corresponding value if found, None otherwise.
    """
    # If top_key is specified, search in the corresponding sub-dictionary
    if top_key is not None:
        return deep_get(d[top_key], key)
    
    if key not in d:
        for _, v in d.items():
            if isinstance(v, dict):
                result = deep_get(v, key)
                if result is not None:
                    return result
    else:
        return d[key]
    

def flatten_policies(single_policy_name: str, single_policy: dict, acc: dict = {}) -> None:
    """
    Flatten a nested single policy into a list of single policies.

    :param single_policy_name (str): Name of the single policy to be flattened
    :param single_policy (dict): Single policy to be flattened
    :param acc (dict): Accumulator dictionary
    """
    if "protocols" in single_policy:
        # Policy is not nested
        acc[single_policy_name] = single_policy
    else:
        # Policy is nested
        for subpolicy in single_policy:
            flatten_policies(subpolicy, single_policy[subpolicy], acc)


def flatten_interaction(interaction: dict) -> dict:
    """
    Flatten an interaction to a dictionary containing all single policies.

    :param interaction (dict): Interaction to be flattened
    :return: Flattened interaction
    """
    acc = {}
    for single_policy_name, single_policy in interaction.items():
        flatten_policies(single_policy_name, single_policy, acc)
    return acc


def is_one_off(policy: dict) -> bool:
    """
    Check if the given policy is a one-off policy.

    :param policy: Policy to check.
    :return: True if the policy is a one-off policy, False otherwise.
    """
    return not "stats" in policy


def is_transient(policy: dict) -> bool:
    """
    Check if the given policy is a transient policy.

    :param policy: Policy to check.
    :return: True if the policy is a transient policy, False otherwise.
    """
    return "stats" in policy and ("packet-count" in policy["stats"] or "duration" in policy["stats"])


def is_periodic(policy: dict) -> bool:
    """
    Check if the given policy is a periodic policy.

    :param policy: Policy to check.
    :return: True if the policy is a periodic policy, False otherwise.
    """
    return bool(policy.get("stats", {}).get("rate", None))


def is_bidirectional(policy: dict) -> bool:
    """
    Check if the given policy is a bidirectional policy.

    :param policy: Policy to check.
    :return: True if the policy is a bidirectional policy, False otherwise.
    """
    return policy.get("bidirectional", False)


def is_backwards(policy_name: str) -> bool:
    """
    Check if the given policy is backwards.

    :param policy_name: Policy name to check.
    :return: True if the policy is backwards, False otherwise.
    """
    return policy_name.endswith("-backward")


def expected_verdict_drop(row: dict, reason: str, interaction_name: str = None) -> None:
    """
    Set the expected verdict of the given row to DROP
    for the given reason, and log the verdict

    :param row: Row to set the expected verdict for.
    :param reason: Reason for the expected verdict.
    :param interaction_name: [Optional] Interaction name.
    """
    row["expected_verdict"] = DROP
    row["reason"] = reason
    if reason == "EDITED":
        logging.info(f"Packet #{row['id']} was edited. Expected verdict is DROP.")
    elif reason == "INTERACTION":
        logging.info(f"Previous step in interaction {interaction_name} " +
                     f"for packet #{row['id']}. " +
                      "was not found with ACCEPT verdict. " +
                     f"Expected verdict is DROP.")
        

def is_compliant(packet: dict, edit: dict, profile: dict) -> bool:
    """
    Check if the given edited packet is still compliant with the given profile.
    For now, only check (m)DNS packets, on the qtype field.
    TODO: extend for all protocols.

    :param packet: Packet to check.
    :param edit: Edit applied to the packet.
    :param profile: Profile to check against.
    :return: True if the packet is compliant, False otherwise.
    """
    # Do not consider non-(m)DNS packets
    if edit["protocol"] != "DNS" and edit["protocol"] != "mDNS":
        return False
    # Packet is mDNS, and edited field is qr flag -> always compliant
    if edit["protocol"] == "mDNS" and edit["field"] == "qr":
        return True
    # Do not consider (m)DNS packets for which the edited field is not qtype
    if edit["field"] != "qtype":
        return False

    # Packet is (m)DNS and edited field is qtype
    # Check if the new qtype is compliant for the given policy
    protocol = edit["protocol"].lower()
    interaction_name, policy_name = packet["policy"].split("#")
    if policy_name.endswith("-backward"):
        # Strip "-backward" suffix
        policy_name = policy_name.replace("-backward", "")
    policy = {}
    if interaction_name == "single":
        policy = deep_get(profile, policy_name, "single-policies")
    else:
        policy = deep_get(profile, policy_name, "interactions")

    # Error checking
    if protocol not in policy["protocols"]:
        return False

    dns_valid_types = policy["protocols"][protocol].get("qtype", None)
    if dns_valid_types is None:
        # Packet is not matched on DNS qtype
        return False
    
    # Packet is matched on DNS qtype
    new_qtype = DNS_RR_TYPES.get(int(edit["new_value"]), 0)
    if isinstance(dns_valid_types, list):
        # List of valid qtypes
        return new_qtype in dns_valid_types
    else:
        # Only one valid qtype
        return new_qtype == dns_valid_types


# Program entry point
if __name__ == "__main__":

    ### GLOBAL VARIABLES ###
    script_name = os.path.basename(__file__)
    script_path = Path(os.path.abspath(__file__))
    script_dir = script_path.parents[0]
    parent_dir = script_path.parents[1]
    base_dir = script_path.parents[3]
    ground_truth_dir = os.path.join(parent_dir, "ground-truth")
    devices_dir = os.path.join(base_dir, "devices")

    ### LOGGING CONFIGURATION ###
    logging.basicConfig(level=logging.INFO)
    logging.info(f"Starting {script_name}")

    ### READ DATA ###
    device_pcaps = {}
    device_pcaps_file = os.path.join(parent_dir, "device-pcaps.json")
    with open(device_pcaps_file, "r") as f:
        device_pcaps = json.load(f)
    logging.info("Read PCAP database.")


    ### MAIN PROGRAM ###

    # Loop on devices
    for device in device_pcaps:
        device_logs_dir = os.path.join(script_dir, device, "merged")

        # Check if device directory exists
        if not os.path.isdir(device_logs_dir):
            logging.warning(f"Device directory {device_logs_dir} does not exist. Skipping.")
            continue

        device_ground_truth_dir = os.path.join(ground_truth_dir, device)
        device_dir = os.path.join(devices_dir, device)
        device_traces_dir = os.path.join(device_dir, "traces")
        device_edited_log_dir = os.path.join(device_traces_dir, "edited", "csv")
        device_final_dir = os.path.join(script_dir, device, "final")
        os.makedirs(device_final_dir, exist_ok=True)

        # Device YAML profile
        device_profile_file = os.path.join(device_dir, "profile.yaml")
        profile = {}
        with open(device_profile_file, "r") as f:
            profile = yaml.load(f, IncludeLoader)

        # Loop on CSV log files
        log_files = sorted(os.listdir(device_logs_dir))
        for log_file_name in log_files:
            scenario = log_file_name.split(".")[0]
            log_file_name = os.path.join(device_logs_dir, log_file_name)
            logging.info(f"Processing log file {log_file_name}")
            ground_truth_file_name = os.path.join(device_ground_truth_dir, "merged", f"{scenario}.merged.csv")
            edit_log_file_name = os.path.basename(log_file_name.replace(".merged", ""))
            edit_log_file_name = os.path.join(device_edited_log_dir, edit_log_file_name)
            final_log_file_name = os.path.basename(log_file_name.replace(".merged", ".final"))
            final_log_file_name = os.path.join(device_final_dir, final_log_file_name)

            # Open files
            log_file = open(log_file_name, "r")
            log_reader = csv.DictReader(log_file)
            ground_truth_file = open(ground_truth_file_name, "r")
            ground_truth_list = list(csv.DictReader(ground_truth_file, delimiter=","))
            edit_log_file = open(edit_log_file_name, "r")
            edit_log_list = list(csv.DictReader(edit_log_file, delimiter=","))
            final_log_file = open(final_log_file_name, "w")

            # Write final log file header
            fieldnames = log_reader.fieldnames.copy()
            index = fieldnames.index("verdict")
            fieldnames[index] = "actual_verdict"
            fieldnames.insert(index, "expected_verdict")
            fieldnames.append("reason")
            final_log_file_writer = csv.DictWriter(final_log_file, fieldnames=fieldnames)
            final_log_file_writer.writeheader()

            # Process CSV file
            rows = list(log_reader)
            for i in range(len(rows)):
                row = rows[i].copy()
                logging.info(f"Processing packet {row} of file {log_file_name}")
                row["actual_verdict"] = row.pop("verdict")
                ground_truth_rows = [pkt for pkt in ground_truth_list if pkt["id"] == row["id"]]
                any_accept = any(pkt["verdict"] == ACCEPT for pkt in ground_truth_rows)
                ground_truth_verdict = ACCEPT if any_accept else DROP

                # Check if packet was edited
                try:
                    edited_packet = next(packet for packet in edit_log_list if packet["new_hash"] == row["hash"] and packet["new_hash"] != packet["old_hash"])
                except StopIteration:
                    # Packet was not edited
                    pass
                else:
                    if not is_compliant(row, edited_packet, profile):
                        # Packet was edited and is not compliant
                        # Expected verdict is DROP
                        expected_verdict_drop(row, "EDITED")
                        final_log_file_writer.writerow(row)
                        logging.info(f"Final log file {final_log_file_name}: wrote {row}")
                        continue

                # Packet was not edited
                # Must check if packet is part of an interaction containing previously edited packets
                
                # Get packet interaction and policy
                try:
                    interaction_name, policy_name = row["policy"].split("#")
                except ValueError:
                    # No policy name, packet was dropped by NFTables
                    # Expected verdict is equal to ground truth
                    row["expected_verdict"] = ground_truth_verdict
                    row["reason"] = "GROUND_TRUTH"
                    logging.info(f"Packet #{row['id']} dropped by NFTables. " +
                                    f"Expected verdict is {ground_truth_verdict}.")
                    final_log_file_writer.writerow(row)
                    logging.info(f"Final log file {final_log_file_name}: wrote {row}")
                    continue

                # Interaction and policy were successfully retrieved
                fwd_policy_name = policy_name.replace("-backward", "")
                logging.info(f"Packet #{row['id']} for policy {policy_name} not edited. " +
                            f"Checking interaction {interaction_name} for edited packets.")
                
                policy = {}
                is_first = False  # Whether packet is first in interaction
                expected_previous_policy_names = []

                if interaction_name == "single":
                    # Individual policy
                    policy = profile.get("single-policies", {}).get(fwd_policy_name, {})
                    if is_one_off(policy) and is_bidirectional(policy):
                        if is_backwards(policy_name):
                            # One-off bidirectional backward policy,
                            # search for preceding forward packet
                            is_first = False
                            expected_previous_policy_names.append(fwd_policy_name)
                        else:
                            # One-off bidirectional forward policy,
                            # search for preceding backward packet
                            is_first = True
                            expected_previous_policy_names.append(f"{fwd_policy_name}-backward")
                    else:
                        # Unedited individual policy,
                        # either unidirectional one-off,
                        # or transient / periodic.
                        # Expected verdict is equal to ground truth
                        row["expected_verdict"] = row["actual_verdict"]
                        row["reason"] = "GROUND_TRUTH"
                        logging.info(f"Packet #{row['id']} not edited " +
                                        f"and from individual policy {fwd_policy_name}. " +
                                        f"Expected verdict is {row['actual_verdict']}.")
                        final_log_file_writer.writerow(row)
                        logging.info(f"Final log file {final_log_file_name}: wrote {row}")
                        continue
                
                else:
                    # Policy part of an interaction
                    interaction = flatten_interaction(profile.get("interactions", {}).get(interaction_name, {}))
                    policy_names = list(interaction.keys())
                    policy_idx = policy_names.index(fwd_policy_name)
                    policy = interaction[fwd_policy_name]
                    is_first = policy_idx == 0  # Whether policy is first in interaction

                    # Get expected previous policy
                    if (is_one_off(policy) or is_transient(policy)) and is_bidirectional(policy) and is_backwards(policy_name):
                        # Current policy is the backward of a one-off or transient policy
                        expected_previous_policy_names.append(policy_name.replace("-backward", ""))

                    else:
                        # Current policy can be:
                        # - the forward of a one-off policy
                        # - a transient policy
                        # - a periodic policy

                        # Expected previous policy is the previous step in the interaction
                        # (last step if the current policy is the first in the interaction)
                        backtrack_idx = policy_idx - 1
                        while True:
                            expected_previous_policy_name = policy_names[backtrack_idx]
                            expected_previous_policy = interaction[expected_previous_policy_name]
                            if is_one_off(expected_previous_policy) and is_bidirectional(expected_previous_policy):
                                # If previous policy is one-off and bidirectional,
                                # expected previous policy is the backward one
                                expected_previous_policy_name += "-backward"
                            expected_previous_policy_names.append(expected_previous_policy_name)

                            if ( is_transient(expected_previous_policy) or is_periodic(expected_previous_policy) ) and is_bidirectional(expected_previous_policy):
                                # If previous policy is transient or periodic, and bidirectional,
                                # add backward policy to expected previous policies
                                expected_previous_policy_names.append(f"{expected_previous_policy_name}-backward")
                        
                            if is_periodic(expected_previous_policy):
                                # If previous policy is periodic,
                                # add second previous policy to expected previous policies
                                backtrack_idx -= 1
                            else:
                                break

                        
                # Loop backwards starting from current row, in the same interaction
                j = i - 1
                seen_previous_policy = False
                while j >= 0:
                    previous_row = rows[j]

                    if is_default_drop(previous_row["policy"]):
                        j -= 1
                        continue

                    if is_same_interaction(previous_row["policy"], row["policy"]):
                        # Still in same interaction
                        actual_previous_policy_name = previous_row["policy"].split("#")[1]
                        actual_previous_policy_verdict = previous_row["verdict"]

                        if ( (actual_previous_policy_name == policy_name) or
                                (not is_one_off(policy) and is_same_policy(fwd_policy_name, actual_previous_policy_name)) ):
                            # Previous policy is equal to current policy
                            if not is_one_off(policy) and actual_previous_policy_verdict == ACCEPT:
                                # Encountered same policy with ACCEPT verdict
                                # Expected verdict is equal to actual verdict
                                row["expected_verdict"] = row["actual_verdict"]
                                row["reason"] = "GROUND_TRUTH"
                                logging.info(f"Packet {row['id']}: " +
                                                f"same policy {policy_name} encountered with ACCEPT verdict. " +
                                                f"Expected verdict is {row['actual_verdict']}.")
                                break

                            if seen_previous_policy and is_one_off(policy) and actual_previous_policy_verdict == ACCEPT and policy_name not in expected_previous_policy_names:
                                # Current policy should not be this one
                                # Expected verdict is DROP
                                expected_verdict_drop(row, "INTERACTION", interaction_name)
                                break
                            else:
                                # continue iterating backwards to find the previous step
                                j -= 1
                                continue

                        elif actual_previous_policy_name in expected_previous_policy_names:
                            seen_previous_policy = True
                            if actual_previous_policy_verdict == "ACCEPT":
                                # Previous step is present and ACCEPTed
                                # Expected verdict is ACCEPT
                                row["expected_verdict"] = row["actual_verdict"]
                                row["reason"] = "GROUND_TRUTH"
                                logging.info(f"Previous step in interaction {interaction_name} " +
                                                f"for packet #{row['id']}. " +
                                                "has been found with ACCEPT verdict. " +
                                                f"Expected verdict is {row['actual_verdict']}.")
                                break
                            else:
                                # Previous step is present but with DROP verdict
                                # Continue iterating backwards, hoping to find an ACCEPTed one
                                j -= 1
                                continue

                        elif actual_previous_policy_name not in expected_previous_policy_names and actual_previous_policy_verdict == ACCEPT:
                            # Too old previous step with ACCEPT verdict
                            # Did not find ACCEPTed previous step
                            # Expected verdict is DROP
                            expected_verdict_drop(row, "INTERACTION", interaction_name)
                            break

                        else:
                            # Nothing relevant found, continue iterating backwards
                            j -= 1
                            continue

                    else:
                        # Encountered other interaction
                        # Might be a parasite packet
                        # Continue iterating backwards, hoping to find the interaction previous step
                        j -= 1
                        continue

                if j < 0:
                    # Went back to the beginning of the log file,
                    # without finding ACCEPTed previous step.
                    if is_first:
                        # Current policy is the first in its interaction
                        # Expected verdict is ACCEPT
                        row["expected_verdict"] = row["actual_verdict"]
                        row["reason"] = "GROUND_TRUTH"
                        logging.info(f"Packet #{row['id']} not edited " +
                                        f"and from policy {row['policy']}. " +
                                        f"Expected verdict is {row['actual_verdict']}.")
                    else:
                        # Current policy is not the first in its interaction
                        # Expected verdict is DROP
                        expected_verdict_drop(row, "INTERACTION", interaction_name)

                final_log_file_writer.writerow(row)
                logging.info(f"Final log file {final_log_file_name}: wrote {row}")

            # Close files
            log_file.close()
            ground_truth_file.close()
            edit_log_file.close()
            final_log_file.close()
