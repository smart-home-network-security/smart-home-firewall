#!/usr/bin/python3

import os
from pathlib import Path
import csv
import subprocess


### GLOBAL VARIABLES ###
script_name = os.path.basename(__file__)
script_path = Path(os.path.abspath(__file__))
script_dir = script_path.parents[0]
read_one_script = os.path.join(script_dir, "read_one.py")
scenarios= [
    "normal",
    "state",
    "string",
    "lookup"
]


##### MAIN #####
if __name__ == "__main__":

    # Create global result file
    result_file_path = os.path.join(script_dir, "metrics.csv")
    with open(result_file_path, "w") as result_file:
        writer = csv.DictWriter(result_file, fieldnames=[])

        # Iterate over scenarios
        for i, scenario in enumerate(scenarios):

            # Read result for each scenario
            top_output_path = os.path.join(script_dir, scenario, "top.txt")
            cmd = f"python3 {read_one_script} {top_output_path}"
            subprocess.run(cmd.split())

            scenario_result_path = os.path.join(script_dir, scenario, "metrics.csv")
            with open(scenario_result_path, "r") as scenario_result_file:
                # Read CSV file
                reader = csv.DictReader(scenario_result_file)
                if i == 0:
                    # If first scenario, write header
                    writer.fieldnames = reader.fieldnames
                    writer.writeheader()
                all_rows = list(reader)

                # Write rows
                writer.writerows(all_rows)
