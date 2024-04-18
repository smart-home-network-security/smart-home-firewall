#!/usr/bin/python3

"""
Merge NFQueue and NFLog CSV logs into a single file.
"""

import os
from pathlib import Path
import json
import csv
import re
import logging
from typing import Union, Tuple


# Verdict values
ACCEPT = "ACCEPT"
DROP = "DROP"
QUEUE = "QUEUE"


def get_all_packets(rows: list, hash: str, timestamp: Union[float, str], start_idx: int = 0) -> Tuple[list, int]:
    """
    Retrieve all packets from a list which have the given hash value and timestamp,
    and represent the same packet matched with different policies.
    As packet list is sorted, stop when packet timestamp is exceeded.

    :param rows: list of rows
    :param hash: packet hash value
    :param timestamp: packet timestamp
    :param start_idx: Optional; index to start from (default: 0)
    :return:
        - list of rows with the given hash value
        - index following the last row with the given hash value
    """
    timestamp = float(timestamp)
    acc = []
    result_idx = start_idx - 1
    i = start_idx
    for row in rows[i:]:
        current_timestamp = float(row["timestamp"])
        if current_timestamp > timestamp:
            # As packet list is sorted, stop when timestamp is exceeded
            if current_timestamp == 1678880460.621344:
                print(acc, result_idx + 1)
            break
        
        # Timestamp is not exceeded yet
        if row["hash"] == hash and current_timestamp == timestamp:
            acc.append(row)
            result_idx = i
        i += 1
    return acc, result_idx + 1


def get_ground_truth_policy(ground_truth_list: list, id: int) -> str:
    """
    Retrieve the ground truth policy from the ground truth list,
    for the given packet ID.

    :param ground_truth_list: ground truth list
    :param id: packet ID
    :return: ground truth policy for this packet
    """
    try:
        ground_truth_row = next(row for row in ground_truth_list if row["id"] == id)
    except StopIteration:
        # Corresponding ground truth row not found
        logging.warning(f"Ground truth row not found for NFLog row #{id}.")
        return None
    else:
        # Corresponding ground truth row found
        return ground_truth_row["policy"]


def merge_rows(nflog_row: dict, nfq_row: dict, ground_truth_policy: str) -> dict:
    """
    Merge corresponding NFLog and NFQueue rows into a single row.

    :param nflog_row: NFLog row
    :param nfq_row: NFQueue row
    :param ground_truth_policy: ground truth policy corresponding to this packet
    :return: merged row
    """
    merged_row = nfq_row.copy()
    merged_row["id"] = nflog_row["id"]
    if merged_row["verdict"] == DROP and ground_truth_policy is not None:
        merged_row["policy"] = ground_truth_policy
    elif not merged_row["policy"]:
        merged_row["policy"] = nflog_row["policy"]
    return merged_row


# Program entry point
if __name__ == "__main__":

    ### GLOBAL VARIABLES ###
    script_name = os.path.basename(__file__)
    script_path = Path(os.path.abspath(__file__))
    script_dir = script_path.parents[0]
    parent_dir = script_path.parents[1]

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
        device_logs_dir = os.path.join(script_dir, device)
        # Check if device directory exists
        if not os.path.isdir(device_logs_dir):
            logging.warning(f"Device directory {device_logs_dir} does not exist. Skipping.")
            continue

        ground_truth_dir = os.path.join(parent_dir, "ground-truth", device, "merged")
        # Check if device ground truth directory exists
        if not os.path.isdir(device_logs_dir):
            logging.warning(f"Device ground truth directory {ground_truth_dir} does not exist. Skipping.")
            continue

        logging.info(f"Processing CSV logs for device {device}.")

        # Check if logs directories exist
        nflog_dir = os.path.join(device_logs_dir, "nflog")
        nfq_dir = os.path.join(device_logs_dir, "nfq")
        if not os.path.isdir(nflog_dir) or not os.path.isdir(nfq_dir):
            logging.warning(f"Logs directory for device {device} does not exist. Skipping.")
            continue

        # Loop on CSV log files
        merged_logs_dir = os.path.join(device_logs_dir, "merged")
        os.makedirs(merged_logs_dir, exist_ok=True)
        nflog_files = sorted(os.listdir(nflog_dir))
        for nflog_file_name in nflog_files:
            stem = Path(nflog_file_name).stem
            nflog_file_name = os.path.join(nflog_dir, nflog_file_name)
            # Corresponding NFQueue log file
            nfq_file_name = os.path.join(nfq_dir, f"{stem.replace('.log', '.nfq')}.csv")
            # Merged CSV log file
            merged_file_name = os.path.join(merged_logs_dir, f"{stem.replace('.log', '.merged')}.csv")
            # Corresponding ground truth log file
            pattern = r"\.edit-\d+"
            ground_truth_stem = Path(merged_file_name).stem
            ground_truth_stem = re.sub(pattern, "", ground_truth_stem)
            ground_truth_file_name = os.path.join(ground_truth_dir, f"{ground_truth_stem}.csv")
            
            # Open files
            logging.info(f"Open NFLog CSV file {nflog_file_name}")
            nflog_file = open(nflog_file_name, "r")
            logging.info(f"Open NFQueue CSV file {nfq_file_name}")
            nfq_file = open(nfq_file_name, "r")
            logging.info(f"Open ground truth CSV file {merged_file_name}")
            ground_truth_file = open(ground_truth_file_name, "r")
            logging.info(f"Open merged CSV file {merged_file_name}")
            merged_file = open(merged_file_name, "w")

            # Initialize CSV handlers
            nflog_reader = csv.DictReader(nflog_file)
            nfq_list = list(csv.DictReader(nfq_file))
            nfq_list.sort(key=lambda row: float(row["timestamp"]))
            ground_truth_list = list(csv.DictReader(ground_truth_file))
            merged_writer = csv.DictWriter(merged_file, fieldnames=nflog_reader.fieldnames)
            merged_writer.writeheader()

            # Process NFLog file
            nflog_list = list(nflog_reader)
            nflog_list.sort(key=lambda row: row["timestamp"])
            nflog_row_idx = 0
            nfq_row_idx = 0
            while nflog_row_idx < len(nflog_list):
                nflog_row = nflog_list[nflog_row_idx]
                verdict = nflog_row["verdict"]

                # Rows which do not have the QUEUE verdict: write as is
                if verdict != QUEUE:
                    # Get corresponding ground truth policy name
                    ground_truth_policy = get_ground_truth_policy(ground_truth_list, nflog_row["id"])
                    merged_row = nflog_row.copy()
                    if verdict == DROP and ground_truth_policy is not None:
                        merged_row["policy"] = ground_truth_policy
                    merged_writer.writerow(merged_row)
                    logging.info(f"Wrote nflog row: {merged_row}.")
                    nflog_row_idx += 1
                    continue
                
                # Rows which have the QUEUE verdict: merge with corresponding NFQueue row
                hash = nflog_row["hash"]
                timestamp = float(nflog_row["timestamp"])

                # Get all NFLog rows with the same hash and timestamp
                # (i.e. duplicate packets sent at the same time)
                nflog_rows, nflog_row_idx = get_all_packets(nflog_list, hash, timestamp, nflog_row_idx)
                
                # Get all corresponding NFQueue rows with the same hash and timestamp
                nfq_rows, nfq_row_idx = get_all_packets(nfq_list, hash, timestamp, nfq_row_idx)

                if len(nfq_rows) == 0:
                    logging.warning(f"NFQueue row not found for NFLog row with hash {nflog_row['hash']} and timestamp {nflog_row['timestamp']}")

                elif len(nflog_rows) == len(nfq_rows):
                    # Each packet was matched with a single policy
                    for nflog_row, nfq_row in zip(nflog_rows, nfq_rows):
                        ground_truth_policy = get_ground_truth_policy(ground_truth_list, nflog_row["id"])
                        merged_row = merge_rows(nflog_row, nfq_row, ground_truth_policy)
                        merged_writer.writerow(merged_row)
                        logging.info(f"Wrote merged row: {merged_row}.")

                elif len(nflog_rows) == 1 and len(nfq_rows) > 1:
                    # One packet was matched with multiple policies
                    ground_truth_policy = get_ground_truth_policy(ground_truth_list, nflog_row["id"])
                    for nfq_row in nfq_rows:
                        merged_row = merge_rows(nflog_row, nfq_row, ground_truth_policy)
                        merged_writer.writerow(merged_row)
                        logging.info(f"Wrote merged row: {merged_row}.")

            # Close files
            nflog_file.close()
            nfq_file.close()
            ground_truth_file.close()
            merged_file.close()
            logging.info(f"Closed all CSV files.")
