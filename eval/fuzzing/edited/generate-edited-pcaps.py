#!/usr/bin/python3

"""
Generate edited PCAPs for firewall evaluation.
"""

# Import libraries
import os
from pathlib import Path
import glob
import shutil
import argparse
import json
import logging
import pcap_fuzzer  # Custom PCAP fuzzing library


def strictly_positive_int(value: any) -> int:
    """
    Custom argparse type for a strictly positive integer value.
    
    :param value: argument value to check
    :return: argument as integer if it is strictly positive
    :raises argparse.ArgumentTypeError: if argument does not represent a strictly positive integer
    """
    try:
        ivalue = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value} does not represent an integer.")
    else:
        if ivalue < 1:
            raise argparse.ArgumentTypeError(f"{value} does not represent a strictly positive integer.")
        return ivalue


# Program entry point
if __name__ == "__main__":

    ### GLOBAL VARIABLES ###
    # Paths
    script_name = os.path.basename(__file__)
    script_path = Path(os.path.abspath(__file__))
    script_dir = script_path.parents[0]
    parent_dir = script_path.parents[1]
    base_dir = script_path.parents[3]
    devices_dir = os.path.join(base_dir, "devices")

    ### LOGGING CONFIGURATION ###
    logging.basicConfig(level=logging.INFO)
    logging.info(f"Starting {script_name}")

    ### ARGUMENT PARSING ###
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Generate edited PCAPs for firewall evaluation."
    )
    # Optional flag: -n, --number-pcaps
    parser.add_argument("-n", "--number-pcaps", type=strictly_positive_int, default=5,
                        help="Number of edited PCAPs to generate per original PCAP. Must be a strictly positive integer. Default: 5.")
    args = parser.parse_args()

    ### READ DATA ###
    # Device PCAPs
    device_pcaps = {}
    device_pcaps_file = os.path.join(parent_dir, "device-pcaps.json")
    with open(device_pcaps_file, "r") as f:
        device_pcaps = json.load(f)
    logging.info("Read PCAP database.")


    ### MAIN PROGRAM ###

    # Loop on devices
    for device, pcaps in device_pcaps.items():
        device_dir = os.path.join(devices_dir, device)

        # Loop on PCAPs
        for pcap in pcaps:
            pcap_path = os.path.join(device_dir, "traces", pcap)
            pcap_edited_dir = os.path.join(device_dir, "traces", "edited")
            pcap_edited_csv_dir = os.path.join(pcap_edited_dir, "csv")
            os.makedirs(pcap_edited_csv_dir, exist_ok=True)
            pcap_edited_pcap_dir = os.path.join(pcap_edited_dir, "pcap")
            os.makedirs(pcap_edited_pcap_dir, exist_ok=True)

            # Generate edited PCAPs
            for i in range(1, args.number_pcaps + 1):
                pcap_edited_basename = os.path.basename(pcap_path).replace(".pcap", f".edit-{i}.pcap")
                pcap_edited_path = os.path.join(pcap_edited_dir, pcap_edited_basename)

                # Generate edited PCAP
                pcap_fuzzer.fuzz_pcaps(pcaps=pcap_path, output=pcap_edited_path, random_range=5)
                logging.info(f"Generated edited PCAP {pcap_edited_basename}.")

            # Move files to correct directories
            for file in glob.glob(os.path.join(pcap_edited_dir, "*.csv")):
                shutil.copy(file, pcap_edited_csv_dir)
                os.remove(file)
            for file in glob.glob(os.path.join(pcap_edited_dir, "*.pcap")):
                shutil.copy(file, pcap_edited_pcap_dir)
                os.remove(file)
