import os
import argparse
import yaml
from yaml_loaders.IncludeLoader import IncludeLoader


##### MAIN #####
if __name__ == "__main__":

    # Command line arguments
    description = "Expand a device YAML profile to its full form."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("profile", type=str, help="Path to the device YAML profile")
    args = parser.parse_args()

    # Retrieve useful paths
    script_path = os.path.abspath(os.path.dirname(__file__))      # This script's path
    device_path = os.path.abspath(os.path.dirname(args.profile))  # Device profile's path

    # Load the device profile
    with open(args.profile, "r") as f_a:
        
        # Load YAML profile with custom loader
        profile = yaml.load(f_a, IncludeLoader)

        # Write the expanded profile to a new file
        expanded_profile_path = os.path.join(device_path, "expanded_profile.yaml")
        with open(expanded_profile_path, "w") as f_b:
            yaml.dump(profile, f_b, default_flow_style=False)
