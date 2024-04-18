#!/usr/bin/python3

# Plot confusion matrix

import os
from pathlib import Path
import json
import csv
import logging

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sn
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score


### GLOBAL VARIABLES ###
script_name = os.path.basename(__file__)
script_path = Path(os.path.abspath(__file__))
script_dir = script_path.parents[0]
parent_dir = script_path.parents[1]


def compute_metrics(device_pcaps: dict) -> dict:
    """
    Compute all metrics.

    :param device_pcaps: dictionary of device PCAPs
    """
    # All metrics
    metrics = {}

    # Metrics for confusion matrix per packet
    expected = []
    actual = []
    labels = ["ACCEPT", "DROP"]

    # Metrics for packet verdict per policy
    per_policy = {}

    # Metrics for packet verdict per interaction
    per_interaction = {}

    # Loop on devices
    for device in device_pcaps:
        device_logs_dir = os.path.join(script_dir, device, "final")

        # Check if device directory exists
        if not os.path.isdir(device_logs_dir):
            logging.warning(f"Device directory {device_logs_dir} does not exist. Skipping.")
            continue

        # Loop on CSV log files
        csv_files = sorted(os.listdir(device_logs_dir))
        for csv_file in csv_files:
            csv_file = os.path.join(device_logs_dir, csv_file)
            with open(csv_file, "r") as file:
                reader = csv.DictReader(file)
                for row in reader:

                    # Confusion matrix per packet
                    expected.append(row["expected_verdict"])
                    actual.append(row["actual_verdict"])

                    # Packet verdict per policy
                    policy = row["policy"]
                    if policy not in per_policy:
                        per_policy[policy] = {"expected": [], "actual": [], "labels": labels}
                    per_policy[policy]["expected"].append(row["expected_verdict"])
                    per_policy[policy]["actual"].append(row["actual_verdict"])

                    """
                    # Packet verdict per interaction
                    interaction, policy = policy.split("#")
                    if interaction != "single":
                        if interaction not in per_interaction:
                            per_interaction[interaction] = {"expected": [], "actual": [], "labels": labels}
                        per_interaction[interaction]["expected"].append(row["expected_verdict"])
                        per_interaction[interaction]["actual"].append(row["actual_verdict"])
                    """
                    
    
    metrics["cm_per_packet"] = {"expected": expected, "actual": actual, "labels": labels}
    metrics["per_policy"] = per_policy
    metrics["per_interaction"] = per_interaction
    
    return metrics


def plot_cm_per_packet(metrics: dict) -> None:
    """
    Compute and plot confusion matrix per packet.

    :param device_pcaps: dictionary of device PCAPs
    """
    labels = metrics["labels"]

    # Compute confusion matrix
    cm = confusion_matrix(metrics["expected"], metrics["actual"], labels=labels)

    # Plot confusion matrix
    plt.figure(figsize=(10, 7))
    sn.set(font_scale=1.4)
    sn.heatmap(cm, annot=True, annot_kws={"size": 16}, fmt="d", xticklabels=labels, yticklabels=labels)
    plt.xlabel("Actual")
    plt.ylabel("Expected")
    plt.show()


if __name__ == "__main__":

    ### LOGGING CONFIGURATION ###
    logging.basicConfig(level=logging.INFO)
    logging.info(f"Starting {script_name}")

    ### READ DATA ###
    device_pcaps = {}
    device_pcaps_file = os.path.join(parent_dir, "device-pcaps.json")
    with open(device_pcaps_file, "r") as f:
        device_pcaps = json.load(f)

    
    ### MAIN PROGRAM ###

    metrics = compute_metrics(device_pcaps)

    # Compute accuracy
    accuracy = accuracy_score(metrics["cm_per_packet"]["expected"], metrics["cm_per_packet"]["actual"], normalize=True)
    print(f"Accuracy: {accuracy}")

    # Compute precision
    precision = precision_score(metrics["cm_per_packet"]["expected"], metrics["cm_per_packet"]["actual"], average=None)
    precision_accept = precision[0]
    precision_drop = precision[1]
    print(f"Precision: ACCEPT {precision_accept}; DROP {precision_drop}")

    # Compute recall
    recall = recall_score(metrics["cm_per_packet"]["expected"], metrics["cm_per_packet"]["actual"], average=None)
    recall_accept = recall[0]
    recall_drop = recall[1]
    print(f"Recall: ACCEPT {recall_accept}; DROP {recall_drop}")

    # Compute F1 score
    f1 = f1_score(metrics["cm_per_packet"]["expected"], metrics["cm_per_packet"]["actual"], average=None)
    f1_accept = f1[0]
    f1_drop = f1[1]
    print(f"F1 score: ACCEPT {f1_accept}; DROP {f1_drop}")

    plot_cm_per_packet(metrics["cm_per_packet"])
