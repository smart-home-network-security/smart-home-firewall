#!/usr/bin/python3

"""
Replay edited PCAPs through the firewall
and record each packet's verdict.
"""

import os
from pathlib import Path
import glob
import json
import re
import subprocess
import time
import logging
import sys
import signal
import argparse


### GLOBAL VARIABLES ###
sudo = ""
ssh_name = "router"
ip_addr = "192.168.1.1"
repo_name = "iot-firewall"
firewall = "firewall.nft"
nfqueue = "nfqueue"
nflog = "nflog"


def exit_cleanup(sig, frame):
    """
    SIGINT handler, clean up and exit.
    Kill nfqueue and nflog programs, and flush firewall on target.
    """
    # Kill nfqueue and nflog programs
    run_cmd(f"ssh {ssh_config_file} {ssh_name} \"{sudo} killall -SIGINT {nfqueue}\"")
    run_cmd(f"ssh {ssh_config_file} {ssh_name} \"{sudo} killall -SIGINT {nflog}\"")
    # Flush firewall on target
    run_cmd(f"ssh {ssh_config_file} {ssh_name} \"{sudo} nft flush ruleset\"")
    exit()


def run_cmd(cmd: str) -> int:
    """
    Run a command, and return its exit code.

    :param cmd: command to run
    :return: exit code
    """
    return subprocess.run(cmd, shell=True).returncode


def run_cmd_background(cmd: str) -> None:
    """
    Run a command in the background.

    :param cmd: command to run
    """
    subprocess.Popen(cmd, shell=True)


# Program entry point
if __name__ == "__main__":

    ### VARIABLES ###
    # Host paths
    script_name = os.path.basename(__file__)
    script_path = Path(os.path.abspath(__file__))
    script_dir = script_path.parents[0]
    parent_dir = script_path.parents[1]
    base_dir = script_path.parents[3]
    devices_dir = os.path.join(base_dir, "devices")
    bin_dir = os.path.join(base_dir, "bin")
    ssh_config_file = ""
    log_group = 100

    ### ARGUMENT PARSING ###
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Retrieve ground truth data for firewall evaluation."
    )
    # Positional argument #1: whether to run on VM or router
    parser.add_argument("target", type=str, choices=["vm", "router"], help="Target to run on")
    # Positional argument #2: MAC address of the target
    parser.add_argument("mac_addr", type=str, help="MAC address of the target")
    # Positional argument(s) #3: input PCAP file(s) to replay
    parser.add_argument("input_pcaps", metavar="pcap", type=str, nargs="+", help="Input PCAP file(s) to replay. Use \"all\" to replay all PCAPs.")
    # Option -n: SSH name of the target
    parser.add_argument("-n", "--name", type=str, help="SSH name of the target")
    # Option -a: IP address of the target
    parser.add_argument("-a", "--ip-addr", type=str, help="IP address of the target")
    # Option -i: interface to use
    parser.add_argument("-i", "--interface", type=str, help="Interface to use")
    # Option -p: path to repository root directory on target
    parser.add_argument("-p", "--path", type=str, help="Path to repository root directory on target")
    # Option -o: output log file
    parser.add_argument("-o", "--output", type=str, help="Output log file")
    args = parser.parse_args()

    # Optional argument defaults
    if args.target == "vm":
        sudo = "sudo"
        ssh_config_file = f"-F {os.path.join(parent_dir, 'vagrant-ssh-config')}"
        if args.name is None:
            ssh_name = "default"
        if args.ip_addr is None:
            ip_addr = "192.168.56.37"
        if args.interface is None:
            interface = "vboxnet0"
        if args.path is None:
            args.path = os.path.join("home", "vagrant", repo_name)
    elif args.target == "router":
        if args.name is None:
            ssh_name = "router"
        if args.ip_addr is None:
            ip_addr = "192.168.1.1"
        if args.path is None:
            args.path = os.path.join("root", repo_name)

    # Register SIGINT handler
    signal.signal(signal.SIGINT, exit_cleanup)

    # Get sudo rights
    run_cmd("sudo -v")

    # Flush firewall on target
    run_cmd(f"ssh {ssh_config_file} {ssh_name} \"{sudo} nft flush ruleset\"")

    # Ping target to test connectivity
    exit_code = run_cmd(f"ping -w 5 -I {interface} {args.ip_addr}")
    if exit_code != 0:
        logging.error(f"Cannot ping target at {args.ip_addr} from interface {interface}.")
        exit()

    ### LOGGING CONFIGURATION ###
    if args.output is not None:
        logging.basicConfig(level=logging.INFO, filename=args.output)
    else:
        logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    logging.info(f"Starting {script_name}")

    ### READ DATA ###
    # Device PCAPs
    device_pcaps = {}
    if "all" in args.input_pcaps:
        # Must replay all PCAPs
        # Read device PCAPs from config file
        device_pcaps_file = os.path.join(parent_dir, "device-pcaps.json")
        with open(device_pcaps_file, "r") as f:
            device_pcaps = json.load(f)
    else:
        # Must replay only given PCAPs
        # Read device PCAPs from command line arguments
        for pcap in args.input_pcaps:
            pcap_path = os.path.abspath(pcap)
            device = re.search(r".*/devices/([^/]*)/.*", pcap_path).group(1)
            pcap_basename = os.path.basename(pcap_path)
            pcap_basename = re.sub(r"\.edit-\d", "", pcap_basename)
            device_pcaps[device] = device_pcaps.get(device, []) + [pcap_basename]
    logging.info("Read PCAP data.")


    ### MAIN PROGRAM ###

    # On target: stop nfqueue and nflog programs
    run_cmd(f"ssh {ssh_config_file} {ssh_name} \"{sudo} killall -SIGINT {nfqueue}\"")
    run_cmd(f"ssh {ssh_config_file} {ssh_name} \"{sudo} killall -SIGINT {nflog}\"")

    # Copy nflog program to target
    run_cmd(f"scp {ssh_config_file} {os.path.join(bin_dir, nflog)} {ssh_name}:{args.path}")
    logging.info(f"Copied {nflog} to target at {os.path.join(args.path, nflog)}")

    # Loop on devices
    for device, pcaps in device_pcaps.items():
        device_dir = os.path.join(devices_dir, device)
        target_device_dir = os.path.join(args.path, device)

        # Copy firewall script to target
        run_cmd(f"scp {ssh_config_file} {os.path.join(device_dir, firewall)} {ssh_name}:{target_device_dir}")
        logging.info(f"Copied {device} firewall to target at {os.path.join(target_device_dir, firewall)}")
        # Copy nfqueue program to target
        device_nfqueue = os.path.join(target_device_dir, nfqueue)
        run_cmd(f"scp {ssh_config_file} {os.path.join(bin_dir, device)} {ssh_name}:{device_nfqueue}")
        logging.info(f"Copied {device} {nfqueue} program to target at {device_nfqueue}")

        # Loop on edited PCAPs
        edited_dir = os.path.join(devices_dir, device, "traces", "edited", "pcap")
        all_edited_pcaps = sorted(glob.glob(os.path.join(edited_dir, "*.pcap")))
        for pcap in pcaps:
            pcap_stem = Path(pcap).stem
            edited_pcaps = [p for p in all_edited_pcaps if pcap_stem in p]
            for edited_pcap in edited_pcaps:

                # Keep-alive for sudo rights
                run_cmd("sudo -v")

                # Restart firewall on target
                run_cmd(f"ssh {ssh_config_file} {ssh_name} \"{sudo} nft flush ruleset\"")
                logging.info("Flushed firewall on the target.")
                run_cmd(f"ssh {ssh_config_file} {ssh_name} \"{sudo} nft -f {os.path.join(target_device_dir, firewall)}\"")
                logging.info("Enabled firewall on the target.")

                # Start nfqueue on target
                target_log_dir = os.path.join(target_device_dir, "log")
                run_cmd(f"ssh {ssh_config_file} {ssh_name} \"mkdir -p {target_log_dir}\"")
                nfq_csv_file = f"{Path(edited_pcap).stem}.nfq.csv"
                nfq_csv_file = os.path.join(target_device_dir, target_log_dir, nfq_csv_file)
                cmd = f"ssh {ssh_config_file} {ssh_name} \"{sudo} {os.path.join(target_device_dir, nfqueue)} > {nfq_csv_file}\""
                run_cmd_background(cmd)
                logging.info(f"Started NFQueue program with command: {cmd}")

                # Start nflog on target
                nflog_csv_file = nfq_csv_file.replace("nfq", "log")
                cmd = f"ssh {ssh_config_file} {ssh_name} \"{sudo} {os.path.join(args.path, nflog)} {log_group} {nflog_csv_file}\""
                run_cmd_background(cmd)
                logging.info(f"Started NFLog program with command: {cmd}")

                time.sleep(1)

                # Replay PCAP
                cmd = f"sudo tcpreplay-edit -T nano -i {interface} --enet-dmac={args.mac_addr} {edited_pcap}"
                run_cmd(cmd)
                logging.info(f"Replayed PCAP with command: {cmd}")

                time.sleep(1)

                # Stop nfqueue on target
                run_cmd(f"ssh {ssh_config_file} {ssh_name} \"{sudo} killall -SIGINT {nfqueue}\"")
                # Stop nflog on target
                run_cmd(f"ssh {ssh_config_file} {ssh_name} \"{sudo} killall -SIGINT {nflog}\"")
                logging.info(f"Killed {device} {nfqueue} and {nflog}")

                time.sleep(1)

                # Copy CSV logs to host
                host_nfq_dir = os.path.join(script_dir, device, "nfq")
                os.makedirs(host_nfq_dir, exist_ok=True)
                run_cmd(f"scp {ssh_config_file} {ssh_name}:{nfq_csv_file} {host_nfq_dir}")
                logging.info(f"Copied file {nfq_csv_file} from target to {host_nfq_dir} on host")
                host_nflog_dir = os.path.join(script_dir, device, "nflog")
                os.makedirs(host_nflog_dir, exist_ok=True)
                run_cmd(f"scp {ssh_config_file} {ssh_name}:{nflog_csv_file} {host_nflog_dir}")
                logging.info(f"Copied file {nflog_csv_file} from target to {host_nflog_dir} on host")

                # Remove CSV logs from target
                run_cmd(f"ssh {ssh_config_file} {ssh_name} \"rm {nfq_csv_file}\"")
                logging.info(f"Removed file {nfq_csv_file} from target")
                run_cmd(f"ssh {ssh_config_file} {ssh_name} \"rm {nflog_csv_file}\"")
                logging.info(f"Removed file {nflog_csv_file} from target")
        
    # Flush firewall on target
    run_cmd(f"ssh {ssh_config_file} {ssh_name} \"{sudo} nft flush ruleset\"")
