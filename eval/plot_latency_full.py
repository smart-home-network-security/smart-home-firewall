#!/usr/bin/python3

import argparse
import os
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib import gridspec
import seaborn as sn


### GLOBAL VARIABLES ###
pi = 80  # Percentile interval
script_name = os.path.basename(__file__)
script_path = Path(os.path.abspath(__file__))
script_dir = script_path.parents[0]

## Variables for benign scenarios
benign_dir = os.path.join(script_dir, "latency")
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

## Variables for attack scenarios
attack_dir = os.path.join(script_dir, "attacks", "new_motion")
attack_cases = {
    "base": os.path.join(attack_dir, "latency-base", "with-firewall"),
    "inter-lan": os.path.join(attack_dir, "interaction", "lan", "latency"),
    "inter-wan": os.path.join(attack_dir, "interaction", "wan", "latency"),
    "stats": os.path.join(attack_dir, "stats", "latency"),
    "proto": os.path.join(attack_dir, "proto", "latency")
}


def percentile_interval(pi: str) -> int:
    """
    Argparse type for a percentile interval,
    i.e. an integer between 0 and 100.

    :param pi: input percentile interval
    :return: percentile interval as an integer
    :raises argparse.ArgumentTypeError: if the input is not a valid percentile interval
    """
    pi = int(pi)
    if pi < 0 or pi > 100:
        raise argparse.ArgumentTypeError(f"{pi} is not a valid percentile interval")
    return pi


def build_benign_df(devices: list) -> pd.DataFrame:
    """
    Compute mean and standard deviation of the latency
    measured for each device and each experimental scenario.

    :param devices: list of devices
    :return: pandas DataFrame containing the latency data per device and scenario
    """
    # Result DataFrame, will be populated
    columns = ["device", "scenario", "latency"]
    df = pd.DataFrame(columns=columns)

    # Iterate over devices and scenarios
    for device in devices:
        # Read latencies for the 3 individual scenarios
        device_path = os.path.join(benign_dir, device)
        for scenario in scenarios:
            scenario_path = os.path.join(device_path, scenario)
            if os.path.isdir(scenario_path) and len(os.listdir(scenario_path)):
                csv_file_name = f"{device}_{scenario}.csv"
                csv_file_path = os.path.join(scenario_path, csv_file_name)
                scenario_df = pd.read_csv(csv_file_path)
                tmp_df = pd.DataFrame({
                    "device": [device]*len(scenario_df),
                    "scenario": [scenario]*len(scenario_df),
                    "latency": scenario_df["latency"].apply(lambda x: x*1000)  # Convert to milliseconds
                })
                df = pd.concat([df, tmp_df], ignore_index=True)
        
        # Read latencies for the "all devices" scenario
        csv_file_path = os.path.join(benign_dir, "all-devices", "my-firewall", "all_my-firewall.csv")
        all_df = pd.read_csv(csv_file_path)
        filtered_df = all_df[all_df["device"] == device]
        tmp_df = pd.DataFrame({
            "device": [device]*len(filtered_df),
            "scenario": ["all-devices"]*len(filtered_df),
            "latency": filtered_df["latency"].apply(lambda x: x*1000)  # Convert to milliseconds
        })
        df = pd.concat([df, tmp_df], ignore_index=True)
    
    return df


def build_attack_df(exp_cases: dict) -> pd.DataFrame:
    """
    Compute mean and 95-percentile interval of the latency
    measured for each attack type and experimental scenario.

    :param exp_cases: dictionary of all experimental cases 
    :return: pandas DataFrame containing the latency data per attack type and scenario
    """
    # Result DataFrame, will be populated
    columns = ["scenario", "latency"]
    df = pd.DataFrame(columns=columns)

    # Iterate over devices and scenarios
    for scenario, scenario_path in exp_cases.items():
        # Read timestamp list from CSV file
        if os.path.isdir(scenario_path) and len(os.listdir(scenario_path)) > 0:
            csv_file_name = "latency.csv"
            csv_file_path = os.path.join(scenario_path, csv_file_name)
            scenario_df = pd.read_csv(csv_file_path)
            tmp_df = pd.DataFrame({
                "scenario": [scenario]*len(scenario_df),
                "latency": scenario_df["latency"].apply(lambda x: x*1000)  # Convert to milliseconds
            })
            df = pd.concat([df, tmp_df], ignore_index=True)
    
    return df


def plot_benign(df: pd.DataFrame, ax: plt.Axes) -> None:
    """
    Plot latency values as a grouped bar plot.

    :param df: pandas DataFrame containing the latency data per device and scenario
    :param ax: matplotlib axes to plot on
    """
    sn.barplot(
        ax       = ax,
        data     = df,
        x        = "device",
        y        = "latency",
        hue      = "scenario",
        errorbar = ("pi", args.interval),
        errwidth = 1,
        capsize  = 0.1
    )


def plot_attack(df: pd.DataFrame, ax: plt.Axes) -> None:
    """
    Plot latency values as a grouped bar plot.

    :param df: pandas DataFrame containing the latency data per device and scenario
    :param ax: matplotlib axes to plot on
    """
    sn.barplot(
        ax       = ax,
        data     = df,
        x        = "scenario",
        y        = "latency",
        errorbar = ("pi", args.interval),
        errwidth = 1,
        capsize  = 0.1
    )


# Program entry point
if __name__ == "__main__":

    ### COMMAND LINE ARGUMENTS ###
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Combined plot for latency in benign and attack scenarios."
    )
    # Optional argument #1: file to save the plot to
    parser.add_argument("-f", "--file", type=str, help="File to save the plot to")
    # Optional argument #2: percentile interval
    parser.add_argument("-i", "--interval", type=percentile_interval, default=pi, help="Percentile interval")
    # Parse arguments
    args = parser.parse_args()


    ### PLOTS ###

    ## Initialize combined plot
    fig = plt.figure(figsize=(14, 4))
    gs = gridspec.GridSpec(1, 2, width_ratios=[2, 1], wspace=0.2)

    ## Plot benign scenarios
    # Read data
    benign_df = build_benign_df(devices)
    # Plot data
    ax_benign = plt.subplot(gs[0])
    plot_benign(benign_df, ax_benign)
    # Plot metadata
    ax_benign.set_xlabel(None)
    ax_benign.set_ylabel("Latency [ms]")
    ax_benign.legend(title="Scenario", loc="upper right")
    ax_benign.set_title("a. Firewall-induced latency in benign scenarios")

    ## Plot attack scenarios
    # Read data
    attack_df = build_attack_df(attack_cases)
    # Plot data
    ax_attack = plt.subplot(gs[1])
    plot_attack(attack_df, ax_attack)
    # Plot metadata
    ax_attack.set_xlabel(None)
    xticklabels = ["base", "A1", "A2", "B", "C",]
    ax_attack.set_xticklabels(xticklabels)
    ax_attack.set_ylabel("Latency [ms]")
    ax_attack.set_title("b. Firewall-induced latency under attack")

    ## Show or save plot
    #fig.tight_layout()
    if args.file:
        fig.savefig(args.file)
    else:
        plt.show()
