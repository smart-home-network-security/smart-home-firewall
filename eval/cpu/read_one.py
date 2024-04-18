#!/usr/bin/python3

import os
from pathlib import Path
import argparse
import csv
import subprocess


### GLOBAL VARIABLES ###
script_name = os.path.basename(__file__)
script_path = Path(os.path.abspath(__file__))
script_dir = script_path.parents[0]
process_name = "nfqueue"


##### MAIN #####
if __name__ == "__main__":

    ### ARGUMENT PARSING ###
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Extract CPU and memory metrics from raw file, and write them to a CSV file."
    )
    # Positional argument: raw file
    parser.add_argument("raw_file", type=str, help="Raw file containing CPU and memory metrics output from `top`.")
    # Parse arguments
    args = parser.parse_args()
    raw_file_path = os.path.join(script_dir, args.raw_file)
    raw_file_dir = os.path.dirname(raw_file_path)

    # Extract only relevant lines from raw file
    filtered_file_path = os.path.join(raw_file_dir, "filtered.txt")
    cmd = f"grep {process_name} \"{raw_file_path}\" > \"{filtered_file_path}\""
    subprocess.run(cmd, shell=True)

    # Result CSV file
    result_file_path = os.path.join(raw_file_dir, "metrics.csv")
    
    with open(filtered_file_path, "r") as filtered_file:
        with open(result_file_path, "w") as result_file:

            # Initialize CSV writer
            fieldnames = ["scenario", "iteration", "cpu", "memory_size", "memory_percentage"]
            writer = csv.DictWriter(result_file, fieldnames=fieldnames)
            writer.writeheader()

            # Iterate over raw file
            for i, line in enumerate(filtered_file):

                # Get and write values
                split = line.strip().split()
                values = {
                    "scenario": os.path.basename(raw_file_dir),
                    "iteration": i,
                    "memory_size": split[4],
                    "memory_percentage": split[5].replace("%", ""),
                    "cpu": split[6].replace("%", ""),
                }
                writer.writerow(values)
