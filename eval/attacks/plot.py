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
exp_cases = {
    "base": os.path.join(script_dir, "latency-base", "with-firewall"),
    "proto": os.path.join(script_dir, "proto", "latency"),
    "stats": os.path.join(script_dir, "stats", "latency"),
    "inter-lan": os.path.join(script_dir, "interaction", "lan", "latency"),
    "inter-wan": os.path.join(script_dir, "interaction", "wan", "latency")
}


def build_df(exp_cases: dict) -> pd.DataFrame:
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


def bar_plot(df: pd.DataFrame, ax: plt.Axes) -> None:
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
        x     = "scenario",
        y     = "latency"
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
        x     = "scenario",
        y     = "latency",
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
        x     = "scenario",
        y     = "latency",
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
        x     = "scenario",
        y     = "latency",
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


def save_data(df: pd.DataFrame, is_median: bool, data_file: str) -> None:
    """
    Compute mean (or median) and 95-percentile interval of the latency,
    per device and per scenario,
    and save the data to a CSV file.

    :param df: pandas DataFrame containing the latency data per device and scenario
    :param is_median: whether to compute median instead of mean
    :param data_file: file to save the data to
    """
    all_scenarios = exp_cases["tplink-plug_tcp-flood"]
    m_column = ["median"] if is_median else ["mean"]
    data_columns = m_column + ["error_low", "error_high"]
    columns = ["device_attack"]
    for scenario in all_scenarios:
        for data_column in data_columns:
            columns.append(f"{scenario}_{data_column}")
    result_dict = {key: [] for key in columns}

    # Compute mean and 95-percentile interval of the latency
    i = 1
    for device_attack, scenarios in exp_cases.items():
        result_dict["device_attack"].append(i)
        for scenario in scenarios:
            device_df = df[(df["device_attack"] == device_attack) & (df["scenario"] == scenario)]
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
        i += 1
    
    # Write data to CSV file
    result_df = pd.DataFrame(result_dict)
    result_df.to_csv(data_file, index=False)


# Program entry point
if __name__ == "__main__":

    ### COMMAND LINE ARGUMENTS ###
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Plot latency values for each attack type and scenario."
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
    # Parse arguments
    args = parser.parse_args()


    ### PLOTS ###

    # Initialize plot
    fig = plt.figure()
    ax = fig.subplots()

    # Read data
    df = build_df(exp_cases)

    if args.data_file:
        # Save plot data and exit
        save_data(df, args.median, args.data_file)
        exit(0)

    # Plot data
    plot(args.plot_type, df, ax)

    # Plot metadata
    ax.set_title("Latency under attack, per scenario")
    ax.set_xlabel(None)
    ax.set_ylabel("Latency [ms]")
    xticklabels = ["base", "A1", "A2", "B", "C",]
    ax.set_xticklabels(xticklabels)
    
    # Show or save plot
    fig.tight_layout()
    if args.file:
        fig.savefig(args.file)
    else:
        plt.show()
