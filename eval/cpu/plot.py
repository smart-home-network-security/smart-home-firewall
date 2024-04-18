#!/usr/bin/python3

import os
from pathlib import Path
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sn


### GLOBAL VARIABLES ###
script_name = os.path.basename(__file__)
script_path = Path(os.path.abspath(__file__))
script_dir = script_path.parents[0]
data_file = os.path.join(script_dir, "metrics.csv")


##### MAIN #####
if __name__ == "__main__":

    ### COMMAND LINE ARGUMENTS ###
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Plot CPU and memory metrics."
    )
    # Optional argument #1: file to save the plot to
    parser.add_argument("-f", "--file", type=str, help="File to save the plot to")
    args = parser.parse_args()

    # Read CSV data file
    df = pd.read_csv(os.path.join(script_dir, data_file))


    ### PLOT ###

    # Initialize plot
    fig, axes = plt.subplots(1, 2, figsize=(6, 4))

    # Left plot: CPU usage percentage
    sn.barplot(
        ax       = axes[0],
        data     = df,
        x        = "scenario",
        y        = "cpu",
        errorbar = "pi",
        errwidth = 1,
        capsize  = 0.1
    )

    # Right plot: memory usage percentage
    sn.barplot(
        ax       = axes[1],
        data     = df,
        x        = "scenario",
        y        = "memory_percentage",
        errorbar = "pi",
        errwidth = 1,
        capsize  = 0.1
    )

    ## Plot metadata
    # Global title
    #fig.suptitle("CPU and memory metrics per attack scenario")
    # Left plot
    axes[0].set_xlabel("Scenario")
    axes[0].set_ylabel("CPU usage [%]")
    xlabels = ["Normal", "State", "String", "Lookup"]
    axes[0].set_xticklabels(xlabels)
    # Right plot
    axes[1].set_xlabel("Scenario")
    axes[1].set_ylabel("Memory usage [%]")
    axes[1].set_xticklabels(xlabels)

    # Show or save plot
    fig.tight_layout()
    if args.file:
        fig.savefig(args.file)
    else:
        plt.show()
