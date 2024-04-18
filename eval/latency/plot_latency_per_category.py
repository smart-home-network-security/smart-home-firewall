#!/usr/bin/python3

import argparse
import os
import sys
import re
from inspect import getmembers, isfunction
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


def bar_plot(df: pd.DataFrame, ax: plt.Axes) -> None:
    """
    Plot latency values as a grouped bar plot.

    :param df: pandas DataFrame containing the latency data per device and category
    :param ax: matplotlib axes to plot on
    """
    sn.barplot(
        ax       = ax,
        data     = df,
        x        = "device",
        y        = "latency",
        hue      = "category",
        errorbar = "pi",
        errwidth = 1,
        capsize  = 0.1
    )


def box_plot(df: pd.DataFrame, ax: plt.Axes) -> None:
    """
    Plot latency values as a box plot.

    :param df: pandas DataFrame containing the latency data per device and category
    :param ax: matplotlib axes to plot on
    """
    sn.boxplot(
        ax    = ax,
        data  = df,
        x     = "device",
        y     = "latency",
        hue   = "category"
    )


def violin_plot(df: pd.DataFrame, ax: plt.Axes) -> None:
    """
    Plot latency values as a violin plot.

    :param df: pandas DataFrame containing the latency data per device and category
    :param ax: matplotlib axes to plot on
    """
    sn.violinplot(
        ax    = ax,
        data  = df,
        x     = "device",
        y     = "latency",
        hue   = "category",
        split = False,
        width = 5
    )


def scatter_plot(df: pd.DataFrame, ax: plt.Axes) -> None:
    """
    Plot latency values as a scatter plot.

    :param df: pandas DataFrame containing the latency data per device and category
    :param ax: matplotlib axes to plot on
    """
    sn.scatterplot(
        ax    = ax,
        data  = df,
        x     = "device",
        y     = "latency",
        hue   = "category",
        alpha = 0.5
    )

def point_plot(df: pd.DataFrame, ax: plt.Axes) -> None:
    """
    Plot latency values as a point plot.

    :param df: pandas DataFrame containing the latency data per device and category
    :param ax: matplotlib axes to plot on
    """
    sn.pointplot(
        ax    = ax,
        data  = df,
        x     = "device",
        y     = "latency",
        hue   = "category",
        errorbar = "pi",
        errwidth = 1,
        capsize  = 0.1
    )


def plot(plot_type: str, df: pd.DataFrame, ax: plt.Axes) -> None:
    """
    Plot latency values for each device and category.

    :param plot_type: type of plot to generate
    :param df: pandas DataFrame containing the latency data per device and category
    :param ax: matplotlib axes to plot on
    """
    func = getattr(sys.modules[__name__], f"{plot_type}_plot")
    func(df, ax)


def save_data(df: pd.DataFrame, data_file: str) -> None:
    """
    Compute mean and 95-percentile interval of the latency,
    per device and per category,
    and save the data to a CSV file.

    :param df: pandas DataFrame containing the latency data per device and category
    :param data_file: file to save the data to
    """
    df.to_csv(data_file, index=False)


# Program entry point
if __name__ == "__main__":


    ### COMMAND LINE ARGUMENTS ###
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Plot latency values for each device and category."
    )
    # Optional argument #1: plot or save plot data
    parser.add_argument("-d", "--data-file", type=str, help="Do not plot, but save plot data to given file")
    # Optional argument #2: plot type
    pattern = re.compile(r"^(.*)_plot$")
    plot_types = [func[0].split("_")[0] for func in getmembers(sys.modules[__name__], isfunction) if pattern.match(func[0]) is not None]
    parser.add_argument("-p", "--plot-type", type=str, choices=plot_types, default="bar", help="Plot type")
    # Optional argument #3: file to save the plot to
    parser.add_argument("-f", "--file", type=str, help="File to save the plot to")
    # Parse arguments
    args = parser.parse_args()


    ### PLOTS ###

    # Initialize plot
    fig = plt.figure()
    ax = fig.subplots()

    # Read data
    df = build_df(devices)

    if args.data_file:
        # Save plot data and exit
        save_data(df, args.data_file)
        exit(0)

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
