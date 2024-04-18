#!/usr/bin/python3

import os
import argparse
from enum import Enum
from pathlib import Path
import pandas as pd
import matplotlib.lines as mlines
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


def build_per_category_df(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build a DataFrame for plotting latency values as a per-category strip plot.

    :param df: pandas DataFrame containing the latency data per device and scenario
    :return: pandas DataFrame containing the device-agnostic latency data per category
    """
    full_df = pd.DataFrame(columns=["category", "latency", "count"])
    for category in ProtocolCategory:
        filtered_df = df[df["category"] == category.name]
        count = filtered_df.count()["latency"]
        tmp_df = pd.DataFrame({
            "category": [category.name]*len(filtered_df),
            "latency": filtered_df["latency"],
            "count": [count]*len(filtered_df)
        })
        full_df = pd.concat([full_df, tmp_df], ignore_index=True)
    return full_df



def plot_device(ax: plt.Axes, df: pd.DataFrame, device: str) -> None:
    """
    Plot latency values as a strip plot.

    :param ax: matplotlib axes to plot on
    :param df: pandas DataFrame containing the latency data per device and scenario
    """
    full_df = pd.DataFrame(columns=["device", "category", "latency", "count"])
    for category in ProtocolCategory:
        filtered_df = df[(df["device"] == device) & (df["category"] == category.name)]
        count = filtered_df.count()["latency"]
        tmp_df = pd.DataFrame({
            "device": [device]*len(filtered_df),
            "category": [category.name]*len(filtered_df),
            "latency": filtered_df["latency"],
            "count": [count]*len(filtered_df)
        })
        full_df = pd.concat([full_df, tmp_df], ignore_index=True)
    
    sn.stripplot(
        ax    = ax,
        data  = full_df,
        x     = "category",
        y     = "latency",
        hue   = "count"
    )


def plot_category(ax: plt.Axes, df: pd.DataFrame, category: ProtocolCategory) -> None:
    """
    Plot latency values as a strip plot.

    :param ax: matplotlib axes to plot on
    :param df: pandas DataFrame containing the latency data per device and scenario
    """
    full_df = pd.DataFrame(columns=["device", "category", "latency", "count"])
    for device in devices:
        filtered_df = df[(df["device"] == device) & (df["category"] == category.name)]
        count = filtered_df.count()["latency"]
        tmp_df = pd.DataFrame({
            "device": [device]*len(filtered_df),
            "category": [category.name]*len(filtered_df),
            "latency": filtered_df["latency"],
            "count": [count]*len(filtered_df)
        })
        full_df = pd.concat([full_df, tmp_df], ignore_index=True)
    
    sn.stripplot(
        ax    = ax,
        data  = full_df,
        x     = "category",
        y     = "latency",
        hue   = "device"
    )


def plot_per_category(ax: plt.Axes, df: pd.DataFrame) -> list:
    """
    Plot latency values as a strip plot.

    :param ax: matplotlib axes to plot on
    :param df: pandas DataFrame containing the latency data per device and scenario
    :param colors: list of colors palette to use
    :param markers: list of markers to use
    :return: dictionary containing the packet count per category
    """
    packet_count = {category.name: 0 for category in ProtocolCategory}
    full_df = build_per_category_df(df)

    for i, category in enumerate(ProtocolCategory):
        category_df = full_df[full_df["category"] == category.name]
        packet_count[category.name] = category_df["count"].iloc[0]
        
        sn.stripplot(
            ax    = ax,
            data  = category_df,
            x     = "category",
            y     = "latency",
            hue   = "count",
            palette = [colors[i]],
            marker = markers[i]
        )
    
    return packet_count


def plot_all(ax: plt.Axes, df: pd.DataFrame) -> None:
    """
    Plot latency values as a strip plot.

    :param ax: matplotlib axes to plot on
    :param df: pandas DataFrame containing the latency data per device and scenario
    """
    full_df = pd.DataFrame(columns=["device_category", "latency", "count"])
    for device in devices:
        for category in ProtocolCategory:
            device_category = f"{device}_{category.name}"
            filtered_df = df[(df["device"] == device) & (df["category"] == category.name)]
            count = filtered_df.count()["latency"]
            tmp_df = pd.DataFrame({
                "device_category": [device_category]*len(filtered_df),
                "latency": filtered_df["latency"],
                "count": [count]*len(filtered_df)
            })
            full_df = pd.concat([full_df, tmp_df], ignore_index=True)

    sn.stripplot(
        ax    = ax,
        data  = full_df,
        x     = "count",
        y     = "latency",
        hue   = "device_category"
    )


##### MAIN #####
if __name__ == "__main__":

    ### COMMAND LINE ARGUMENTS ###
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Plot latency values for each device and scenario."
    )
    # Optional argument #1: plot or save plot data
    parser.add_argument("-d", "--data-file", type=str, help="Do not plot, but save plot data to given file")
    # Optional argument #2: file to save the plot to
    parser.add_argument("-f", "--file", type=str, help="File to save the plot to")
    args = parser.parse_args()

    # Initialize plot
    fig = plt.figure()
    ax = fig.subplots()

    # Colors and markers
    colors = plt.rcParams["axes.prop_cycle"].by_key()["color"]
    markers = ['o', 'X', '*', 'P']

    # Read data
    df = build_df(devices)
    strip_df = build_per_category_df(df)

    if args.data_file:
        # Save data to CSV file, then exit
        strip_df.to_csv(args.data_file, index=False)
        exit()

    #plot_all(ax, df)
    #plot_device(ax, df, "philips-hue")
    #plot_category(ax, df, ProtocolCategory.A)
    packet_count = plot_per_category(ax, df)

    # Plot metadata
    ax.set_xlabel("Packet category")
    ax.set_ylabel("Latency [ms]")
    #ax.legend(title="Packet count", loc="upper right")

    # Legend
    handles = []
    for i, category in enumerate(ProtocolCategory):
        cat = mlines.Line2D([], [], color=colors[i], marker=markers[i], linestyle="None", label=packet_count[category.name])
        handles.append(cat)
    ax.legend(title="Packet count", handles=handles)

    # Show or save plot
    fig.tight_layout()
    if args.file:
        fig.savefig(args.file)
    else:
        plt.show()
