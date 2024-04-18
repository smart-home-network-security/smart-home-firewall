#!/usr/bin/python3

import os
from pathlib import Path
import subprocess

### GLOBAL VARIABLES ###
script_name = os.path.basename(__file__)
script_path = Path(os.path.abspath(__file__))
script_dir = script_path.parents[0]
read_one_script = os.path.join(script_dir, "read_one.py")
devices = [
    "dlink-cam",
    "philips-hue",
    "smartthings-hub",
    #"smartthings-door",
    #"smartthings-motion",
    #"smartthings-presence",
    "tplink-plug",
    "xiaomi-cam",
    "tuya-motion"
]
scenarios = [
    "no-firewall",
    "base-firewall",
    "my-firewall"
]

# Program entry point
if __name__ == "__main__":

    for device in devices:
        # Read the list of timestamps
        device_path = os.path.join(script_dir, device)
        for scenario in scenarios:
            scenario_dir = os.path.join(device_path, scenario)
            if len(os.listdir(scenario_dir)) > 0:
                cmd = f"python3 {read_one_script} {device} {scenario}"
                subprocess.run(cmd.split())
