#!/usr/bin/python3

import argparse
import os
from pathlib import Path
from enum import Enum
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sn


### GLOBAL VARIABLES ###
script_name = os.path.basename(__file__)
script_path = Path(os.path.abspath(__file__))
script_dir = script_path.parents[0]
scenario = "my-firewall"
devices = [
    "dlink-cam",
    "philips-hue",
    "smartthings-hub",
    #"smartthings-door",
    #"smartthings-motion",
    #"smartthings-presence",
    "tplink-plug",
    "xiaomi-cam"
]

# Protocol categories for grouping
class ProtocolCategory(Enum):
    A = 0
    B = 1
    C = 2
    D = 3


def build_df(devices: list) -> pd.DataFrame:
    """
    Compute mean and standard deviation of the latency
    measured for each device and each experimental scenario.

    :param devices: list of devices
    :return: pandas DataFrame containing the latency data per device and category
    """
    # Result DataFrame, will be populated
    columns = ["device", "category", "latency"]
    df = pd.DataFrame(columns=columns)

    # Iterate over devices and categories
    for device in devices:
        # Read latency from CSV file
        csv_file_name = f"{device}_{scenario}.csv"
        csv_file_path = os.path.join(script_dir, device, scenario, csv_file_name)
        scenario_df = pd.read_csv(csv_file_path)
        for category in ProtocolCategory:
            category_df = scenario_df[scenario_df["protocol_category"] == category.name]
            tmp_df = pd.DataFrame({
                "device": [device]*len(category_df),
                "category": [category.name]*len(category_df),
                "latency": category_df["latency"].apply(lambda x: x*1000)  # Convert to milliseconds
            })
            df = pd.concat([df, tmp_df], ignore_index=True)
    
    return df


def count_plot(df: pd.DataFrame, ax: plt.Axes) -> None:
    """
    Plot count for each device and category.

    :param df: pandas DataFrame containing the latency data per device and category
    :param ax: matplotlib axes to plot on
    """
    sn.countplot(
        ax   = ax,
        data = df,
        x    = "device",
        hue  = "category"
    )


# Program entry point
if __name__ == "__main__":


    ### COMMAND LINE ARGUMENTS ###
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Plot latency values for each device and category."
    )
    # Optional argument #1: file to save the plot to
    parser.add_argument("-f", "--file", type=str, help="File to save the plot to")
    # Parse arguments
    args = parser.parse_args()


    ### PLOTS ###

    # Initialize plot
    fig = plt.figure()
    ax = fig.subplots()

    # Read data
    df = build_df(devices)

    # Plot data
    count_plot(df, ax)

    # Plot metadata
    ax.set(yscale="log")
    ax.set_title("Packet count per device and per protocol category")
    ax.set_ylabel("Packet count")
    ax.legend(loc="upper right")
    
    # Show or save plot
    fig.tight_layout()
    if args.file:
        fig.savefig(args.file)
    else:
        plt.show()
