#!/usr/bin/python3

import os
from pathlib import Path
import argparse
import pandas as pd
import matplotlib.lines as mlines
import matplotlib.pyplot as plt


### GLOBAL VARIABLES ###

script_name = os.path.basename(__file__)
script_path = Path(os.path.abspath(__file__))
script_dir = script_path.parents[0]
data_file = os.path.join(script_dir, "data.csv")


### MAIN ###

if __name__ == "__main__":

    ### COMMAND LINE ARGUMENTS ###
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Plot firewall size metrics per device, w.r.t. profile size."
    )
    # Optional argument: file to save the plot to
    parser.add_argument("-f", "--file", type=str, help="File to save the plot to")
    # Parse arguments
    args = parser.parse_args()

    # Read CSV data file
    df = pd.read_csv(data_file)
    

    ### PLOT ###

    # Initialize plot
    fig, ax_left = plt.subplots(figsize=(8, 4))

    # Get default color cycle
    colors = plt.rcParams["axes.prop_cycle"].by_key()["color"]
    
    # Device markers
    markers = ['o', '1', '+', 'x', '*']

    # Left-hand side y-axis: number of NFTables rules
    for i, (xi, yi, marker) in enumerate(zip(df["num_policies"], df["nft_rules"], markers)):
        ax_left.scatter(xi, yi, color=colors[0], marker=marker, s=100, label=df["device"][i])
    ax_left.set_xlabel("Number of policies")
    ax_left.set_ylabel("Number of NFTables rules")
    ax_left.set_xticks(list(set(df["num_policies"])))
    ax_left.set_yticks(df["nft_rules"])
    

    # Right-hand side y-axis: number of lines of code in the NFQueue source code
    ax_right = ax_left.twinx()
    for i, (xi, yi, marker) in enumerate(zip(df["num_policies"], df["nfq_loc"], markers)):
        if df["device"][i] == "philips-hue":
            marker = "2"
        ax_right.scatter(xi, yi, color=colors[1], marker=marker, s=100, label=df["device"][i])
    #plot_right = ax_right.scatter(df["num_policies"] + 0.1, df["nfq_loc"], color=colors[1], label="LoC in NFQueue source code")
    ax_right.set_xlabel("Number of policies")
    ax_right.set_ylabel("LoC in NFQueue source code")
    ax_right.set_xticks(list(set(df["num_policies"])))

    # Increase the space between subplots
    #plt.subplots_adjust(wspace=0.3)

    # Global title
    #plt.suptitle("Firewall size metrics per device", fontsize=16)


    ## Legends

    # Legend 1: Metrics
    handles_metrics = []
    metrics = ["#NFTables rules", "#NFQueue LoC"]
    for i in range(len(metrics)):
        handle = mlines.Line2D([], [], color=colors[i], marker='s', markersize=10, linestyle="None", label=metrics[i])
        handles_metrics.append(handle)
    legend_metrics = ax_left.legend(title="Metrics", handles=handles_metrics, loc="lower right", bbox_to_anchor=(1.0, 0.4))

    # Legend 2: Devices
    handles_devices = []
    devices = ["dlink-cam", "philips-hue", "smartthings-hub", "tplink-plug", "xiaomi-cam"]
    for i in range(len(devices)):
        handle = mlines.Line2D([], [], color="black", marker=markers[i], markersize=10, linestyle="None", label=devices[i])
        handles_devices.append(handle)
    legend_devices = ax_right.legend(title="Devices", handles=handles_devices, loc="lower right", bbox_to_anchor=(1.0, 0.0))

    # Show or save plot
    fig.tight_layout()
    if args.file:
        fig.savefig(args.file)
    else:
        plt.show()
