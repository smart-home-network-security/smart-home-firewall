#!/usr/bin/python3

import argparse
import os
import sys
import re
from inspect import getmembers, isfunction
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sn


### GLOBAL VARIABLES ###
script_name = os.path.basename(__file__)
script_path = Path(os.path.abspath(__file__))
script_dir = script_path.parents[0]
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
scenarios = [
    "no-firewall",
    "base-firewall",
    "my-firewall"
]


def build_df(devices: list) -> pd.DataFrame:
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
        # Read timestamp list from CSV file
        device_path = os.path.join(script_dir, device)
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
    
    return df


def bar_plot(df: pd.DataFrame, ax: plt.Axes) -> None:
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
        errorbar = "pi",
        errwidth = 1,
        capsize  = 0.1
    )


def box_plot(df: pd.DataFrame, ax: plt.Axes) -> None:
    """
    Plot latency values as a box plot.

    :param df: pandas DataFrame containing the latency data per device and scenario
    :param ax: matplotlib axes to plot on
    """
    sn.boxplot(
        ax    = ax,
        data  = df,
        x     = "device",
        y     = "latency",
        hue   = "scenario"
    )


def violin_plot(df: pd.DataFrame, ax: plt.Axes) -> None:
    """
    Plot latency values as a violin plot.

    :param df: pandas DataFrame containing the latency data per device and scenario
    :param ax: matplotlib axes to plot on
    """
    sn.violinplot(
        ax    = ax,
        data  = df,
        x     = "device",
        y     = "latency",
        hue   = "scenario",
        split = False,
        width = 5
    )


def scatter_plot(df: pd.DataFrame, ax: plt.Axes) -> None:
    """
    Plot latency values as a scatter plot.

    :param df: pandas DataFrame containing the latency data per device and scenario
    :param ax: matplotlib axes to plot on
    """
    sn.scatterplot(
        ax    = ax,
        data  = df,
        x     = "device",
        y     = "latency",
        hue   = "scenario",
        alpha = 0.5
    )

def point_plot(df: pd.DataFrame, ax: plt.Axes) -> None:
    """
    Plot latency values as a point plot.

    :param df: pandas DataFrame containing the latency data per device and scenario
    :param ax: matplotlib axes to plot on
    """
    sn.pointplot(
        ax    = ax,
        data  = df,
        x     = "device",
        y     = "latency",
        hue   = "scenario",
        errorbar = "pi",
        errwidth = 1,
        capsize  = 0.1
    )


def plot(plot_type: str, df: pd.DataFrame, ax: plt.Axes) -> None:
    """
    Plot latency values for each device and scenario.

    :param plot_type: type of plot to generate
    :param df: pandas DataFrame containing the latency data per device and scenario
    :param ax: matplotlib axes to plot on
    """
    func = getattr(sys.modules[__name__], f"{plot_type}_plot")
    func(df, ax)


# Program entry point
if __name__ == "__main__":


    ### COMMAND LINE ARGUMENTS ###
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Plot latency values for each device and scenario."
    )
    # Optional argument #1: plot type
    pattern = re.compile(r"^(.*)_plot$")
    plot_types = [func[0].split("_")[0] for func in getmembers(sys.modules[__name__], isfunction) if pattern.match(func[0]) is not None]
    parser.add_argument("-p", "--plot-type", type=str, choices=plot_types, default="bar", help="Plot type")
    # Optional argument #2: file to save the plot to
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
    plot(args.plot_type, df, ax)

    # Plot metadata
    ax.set_title("Latency")
    ax.set_ylabel("Latency [ms]")
    ax.legend(loc="upper right")
    
    # Show or save plot
    fig.tight_layout()
    if args.file:
        fig.savefig(args.file)
    else:
        plt.show()
