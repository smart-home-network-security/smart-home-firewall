"""
Randomly edit packet fields in a PCAP file.
"""

import os
import argparse
import random
import logging
import csv
import scapy.all as scapy
from scapy.layers import dhcp, dns, http
from scapy.contrib import coap, igmp, igmpv3
from packet.Packet import Packet


def strictly_positive_int(value: any) -> int:
    """
    Custom argparse type for a strictly positive integer value.
    
    :param value: argument value to check
    :return: argument as integer if it is strictly positive
    :raises argparse.ArgumentTypeError: if argument does not represent a strictly positive integer
    """
    try:
        ivalue = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value} does not represent an integer.")
    else:
        if ivalue < 1:
            raise argparse.ArgumentTypeError(f"{value} does not represent a strictly positive integer.")
        return ivalue
    

def must_edit_packet(i: int, packet_numbers: list, random_range: int) -> bool:
    """
    Check if a packet must be edited.

    :param i: packet number (starting from 1)
    :param packet_numbers: list of packet numbers to edit
    :param random_range: upper bound for random range (not included)
    :return: True if packet must be edited, False otherwise
    """
    is_specified = packet_numbers is not None and i in packet_numbers
    is_random = packet_numbers is None and random.randrange(0, random_range) == 0
    return is_specified or is_random


def tweak_pcaps(pcaps: list, output: str, random_range: int = 1, packet_numbers: list = None, dry_run: bool = False) -> None:
    """
    Main functionality of the program:
    (Randomly) edit packet fields in a (list of) PCAP file(s).

    :param pcaps: list of input PCAP files
    :param output: output PCAP file path. Used only if a single input file is specified.
    :param random_range: upper bound for random range (not included)
    :param packet_numbers: list of packet numbers to edit (starting from 1)
    :param dry_run: if True, do not write output PCAP file
    """
    
    # Loop on given input PCAP files
    for input_pcap in pcaps:
        # PCAP file directory
        input_dir = os.path.dirname(input_pcap)

        # Read input PCAP file
        packets = scapy.rdpcap(input_pcap)
        new_packets = []
        logging.info(f"Read input PCAP file: {input_pcap}")

        # Open log CSV file
        csv_log = ""
        if output is not None and len(pcaps) == 1:
            csv_log = output.replace(".pcap", ".csv")
        else:
            csv_dir = os.path.join(input_dir, "csv")
            os.makedirs(csv_dir, exist_ok=True)
            csv_log = os.path.basename(input_pcap).replace(".pcap", ".edit.csv")
            csv_log = os.path.join(csv_dir, csv_log)
        with open(csv_log, "w") as csv_file:
            field_names = ["id", "timestamp", "protocol", "field", "old_value", "new_value", "old_hash", "new_hash"]
            writer = csv.DictWriter(csv_file, fieldnames=field_names)
            writer.writeheader()

            i = 1
            for packet in packets:

                if must_edit_packet(i, packet_numbers, random_range):
                    # Edit packet, if possible
                    last_layer_index = Packet.get_last_layer_index(packet)
                    while True:
                        try:
                            my_packet = Packet.init_packet(packet, i, last_layer_index)
                        except ValueError:
                            # No supported protocol found in packet, skip it
                            new_packets.append(Packet.rebuild_packet(packet))
                            break
                        else:
                            d = my_packet.tweak()
                            if d is None:
                                # Packet was not edited, try editing one layer lower
                                last_layer_index = my_packet.get_layer_index() - 1
                            else:
                                # Packet was edited
                                new_packets.append(my_packet.get_packet())
                                writer.writerow(d)
                                break
                else:
                    # Packet won't be edited
                    new_packets.append(Packet.rebuild_packet(packet))

                i += 1

        # Write output PCAP file
        output_pcap = ""
        if output is not None and len(pcaps) == 1:
            output_pcap = output
        else:
            output_dir = os.path.join(os.path.dirname(input_pcap), "edited")
            os.makedirs(output_dir, exist_ok=True)
            output_pcap = os.path.basename(input_pcap).replace(".pcap", ".edit.pcap")
            output_pcap = os.path.join(output_dir, output_pcap)
        if dry_run:
            logging.info(f"Dry run: did not write output PCAP file: {output_pcap}")
        else:
            scapy.wrpcap(output_pcap, new_packets)
            logging.info(f"Wrote output PCAP file: {output_pcap}")


if __name__ == "__main__":

    # This script's name
    script_name = os.path.basename(__file__)

    ### LOGGING CONFIGURATION ###
    logging.basicConfig(level=logging.INFO)
    logging.info(f"Starting {script_name}")


    ### ARGUMENT PARSING ###
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Randomly edit packet fields in a PCAP file."
    )
    # Positional arguments: input PCAP file(s)
    parser.add_argument("input_pcaps", metavar="pcap", type=str, nargs="+", help="Input PCAP file(s).")
    # Optional flag: -o / --output
    parser.add_argument("-o", "--output", type=str, help="Output PCAP (and CSV) file path. Used only if a single input file is specified. Default: edited/<input_pcap>.edit.pcap")
    # Optional flag: -r / --random-range
    parser.add_argument("-r", "--random-range", type=strictly_positive_int, default=1,
                        help="Upper bound for random range (not included). Must be a strictly positive integer. Default: 1 (edit each packet).")
    # Optional flag: -n / --packet-number
    parser.add_argument("-n", "--packet-number", type=int, action="append",
                        help="Index of the packet to edit, starting form 1. Can be specifed multiple times.")
    # Optional flag: -d / --dry-run
    parser.add_argument("-d", "--dry-run", action="store_true",
                        help="Dry run: do not write output PCAP file.")
    # Parse arguments
    args = parser.parse_args()
    # Verify arguments
    if args.output is not None and len(args.input_pcaps) > 1:
        logging.warning("Multiple input PCAP files specified, ignoring output PCAP file name.")


    ### MAIN PROGRAM ###
    tweak_pcaps(
        pcaps=args.input_pcaps,
        output=args.output,
        random_range=args.random_range,
        packet_numbers=args.packet_number,
        dry_run=args.dry_run
    )
