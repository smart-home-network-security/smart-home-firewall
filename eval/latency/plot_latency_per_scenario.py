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
    "xiaomi-cam",
    "tuya-motion"
]
scenarios = [
    "no-firewall",
    "base-firewall",
    "my-firewall"
]
pi = 80  # Percentile interval


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
        # Read latencies for the 3 individual scenarios
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
        
        # Read latencies for the "all devices" scenario
        csv_file_path = os.path.join(script_dir, "all-devices", "my-firewall", "all_my-firewall.csv")
        all_df = pd.read_csv(csv_file_path)
        filtered_df = all_df[all_df["device"] == device]
        tmp_df = pd.DataFrame({
            "device": [device]*len(filtered_df),
            "scenario": ["all-devices"]*len(filtered_df),
            "latency": filtered_df["latency"].apply(lambda x: x*1000)  # Convert to milliseconds
        })
        df = pd.concat([df, tmp_df], ignore_index=True)
    
    return df


def build_median_df(df: pd.DataFrame) -> pd.DataFrame:
    median_df = pd.DataFrame(columns=["device", "scenario", "latency"])
    return median_df


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
        errorbar = ("pi", args.interval),
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
        errorbar = ("pi", args.interval),
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


def save_data(df: pd.DataFrame, is_median: bool, data_file: str) -> None:
    """
    Compute mean (or median) and 95-percentile interval of the latency,
    per device and per scenario,
    and save the data to a CSV file.

    :param df: pandas DataFrame containing the latency data per device and scenario
    :param is_median: whether to compute the median instead of the mean
    :param data_file: file to save the data to
    """
    all_scenarios = scenarios + ["all-devices"]
    m_column = ["median"] if is_median else ["mean"]
    data_columns = m_column + ["error_low", "error_high"]
    columns = ["device"]
    for scenario in all_scenarios:
        for data_column in data_columns:
            columns.append(f"{scenario}_{data_column}")
    result_dict = {key: [] for key in columns}

    # Compute mean and 95-percentile interval of the latency
    for device in devices:
        result_dict["device"].append(device)
        for scenario in all_scenarios:
            device_df = df[(df["device"] == device) & (df["scenario"] == scenario)]
            val = None
            name = ""
            if is_median:
                val = device_df["latency"].median()
                name = "median"
            else:
                val = device_df["latency"].mean()
                name = "mean"
            result_dict[f"{scenario}_{name}"].append(val)
            result_dict[f"{scenario}_error_low"].append(abs(val - device_df["latency"].quantile(0.025)))
            result_dict[f"{scenario}_error_high"].append(abs(val - device_df["latency"].quantile(0.975)))
    
    # Write data to CSV file
    result_df = pd.DataFrame(result_dict)
    result_df.to_csv(data_file, index=False)


# Program entry point
if __name__ == "__main__":

    ### COMMAND LINE ARGUMENTS ###
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Plot latency values for each device and scenario."
    )
    # Optional argument #1: plot median instead of mean
    parser.add_argument("-m", "--median", action="store_true", help="Plot median instead of mean")
    # Optional argument #2: plot or save plot data
    parser.add_argument("-d", "--data-file", type=str, help="Do not plot, but save plot data to given file")
    # Optional argument #3: plot type
    pattern = re.compile(r"^(.*)_plot$")
    plot_types = [func[0].split("_")[0] for func in getmembers(sys.modules[__name__], isfunction) if pattern.match(func[0]) is not None]
    parser.add_argument("-p", "--plot-type", type=str, choices=plot_types, default="bar", help="Plot type")
    # Optional argument #4: file to save the plot to
    parser.add_argument("-f", "--file", type=str, help="File to save the plot to")
    # Optional argument #5: percentile interval
    parser.add_argument("-i", "--interval", type=percentile_interval, default=pi, help="Percentile interval")
    # Parse arguments
    args = parser.parse_args()


    ### PLOTS ###

    # Initialize plot
    fig, ax = plt.subplots(figsize=(6, 4), dpi=100)

    # Read data
    df = build_df(devices)
    #median_df = build_median_df(df)

    if args.data_file:
        # Save plot data and exit
        save_data(df, args.median, args.data_file)
        exit(0)

    # Plot data
    plot(args.plot_type, df, ax)

    # Plot metadata
    ax.set_xlabel(None)
    ax.set_ylabel("Latency [ms]")
    ax.legend(title="Scenario", loc="upper right")
    
    # Show or save plot
    #fig.tight_layout()
    if args.file:
        fig.savefig(args.file)
    else:
        plt.show()
