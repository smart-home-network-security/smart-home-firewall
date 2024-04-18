#!/usr/bin/python3

import os
from pathlib import Path
import argparse
from bisect import bisect
import hashlib
import csv
import scapy.all as scapy
from typing import Tuple


### GLOBAL VARIABLES ###
script_name = os.path.basename(__file__)
script_path = Path(os.path.abspath(__file__))
script_dir = script_path.parents[0]
all_dirs = [
    os.path.join(script_dir, "latency-base", "with-firewall"),
    os.path.join(script_dir, "proto", "latency"),
    os.path.join(script_dir, "stats", "latency"),
    os.path.join(script_dir, "interaction", "lan", "latency"),
    os.path.join(script_dir, "interaction", "wan", "latency"),
]
all_pcaps = ["lan.pcap", "wlan2.4.pcap", "wlan5.0.pcap", "wan.pcap"]

device = "tplink-plug"
device_data = {
    "dlink-cam": {
        "pcap": "wlan2.4.pcap",
        "mac":  "b0:c5:54:43:54:83",
        "ipv4": "192.168.1.115",
    },
    "philips-hue": {
        "pcap": "lan.pcap",
        "mac":  "00:17:88:74:c2:dc",
        "ipv4": "192.168.1.141",
        "ipv6": "fe80::217:88ff:fe74:c2dc"
    },
    "tplink-plug": {
        "pcap": "wlan2.4.pcap",
        "mac":  "50:c7:bf:ed:0a:54",
        "ipv4": "192.168.1.135"
    },
    "xiaomi-cam": {
        "pcap": "wlan2.4.pcap",
        "mac":  "78:8b:2a:b2:20:ea",
        "ipv4": "192.168.1.161"
    },
    "tuya-motion": {
        "pcap": "wlan2.4.pcap",
        "mac":  "a0:92:08:7b:03:1c",
        "ipv4": "192.168.1.102"
    },
    "smartthings-hub": {
        "pcap": "lan.pcap",
        "mac":  "d0:52:a8:72:aa:27",
        "ipv4": "192.168.1.223",
        "ipv6": "fddd:ed18:f05b:0:d8a3:adc0:f68f:e5cf"
    },
    "amazon-echo": {
        "pcap": "wlan2.4.pcap",
        "mac":  "50:dc:e7:a2:d8:95",
        "ipv4": "192.168.1.150",
        "ipv6": "fddd:ed18:f05b:0:adef:a05d:fcbe:afc9"
    },
    "phone": {
        "pcap": "wlan5.0.pcap",
        "mac":  "3c:cd:5d:a2:a9:d7",
        "ipv4": "192.168.1.222",
        "ipv6": "fddd:ed18:f05b:0:6413:9c13:5391:3136"
    }
}


def get_packet_hash(packet: scapy.Packet) -> str:
    """
    Compute the SHA256 hash value of a packet.

    :param packet: packet to compute the hash for
    :return: SHA256 hash value for the given packet
    """
    return hashlib.sha256(bytes(packet)).hexdigest()


def search_packet(packets: list, timestamps: list, from_timestamp: float, hash: str) -> dict:
    """
    Search for a packet with the given hash in a list of packet hashes,
    starting from a given timestamp.

    :param packets: list of packet hashes to search
    :param from_timestamp: timestamp from which to start searching
    :param hash: hash value of the packet to search for
    :return: dictionary containing packet data if found, None otherwise
    """
    start_idx = bisect(timestamps, from_timestamp)
    return next((packet for packet in packets[start_idx:] if packet["hash"] == hash and not packet["is_initial"]), None)


def is_addr_for_device(addr: str, device: str, protocol: str) -> bool:
    """
    Check if the given address is for the given device.

    :param addr: address to check
    :param device: device to check
    :param protocol: type of address to check (mac, ipv4 or ipv6)
    :return: True if the address is for the device, False otherwise
    """
    device_addr = device_data[device].get(protocol, None)
    if device_addr is None:
        return False
    
    if isinstance(device_addr, list):
        return addr in device_addr
    else:
        return addr == device_addr


def get_map_addr_pcap(protocol: str, this_device: str) -> dict:
    """
    Return a dictionary mapping the devices' addresses
    to their corresponding base PCAP file,
    except for the phone and the device under test.

    :param protocol: type of address to get (mac, ipv4 or ipv6)
    :param this_device: device under test
    :return: dictionary mapping addresses to PCAP files
    """
    map_addr_pcap = {}
    if protocol == "ipv4":
        map_addr_pcap["0.0.0.0"] = device_data[this_device]["pcap"]
    for _, data in device_data.items():
        try:
            map_addr_pcap[data[protocol]] = data["pcap"]
        except KeyError:
            pass
    return map_addr_pcap


def get_other_pcap(packet: scapy.Packet, maps_addr_pcap: dict) -> str:
    """
    Get the other PCAP file corresponding to a given packet.

    :param packet: packet to get the other PCAP file for
    :param maps_addr_pcap: dictionary mapping addresses (MAC, IPv4 and IPv6) to PCAP files
    :return: name of the other PCAP file,
             or None if the packet contains neither an IP or an ARP layer
    """
    if packet.haslayer(scapy.IP):
        # Packet has an IP layer
        layer = packet.getlayer(scapy.IP)
        protocol = f"ipv{layer.version}"
        dst = layer.dst
    elif packet.haslayer(scapy.ARP):
        # Packet has an ARP layer
        layer = packet.getlayer(scapy.ARP)
        protocol = "ipv4"
        dst = layer.pdst
    else:
        # Packet does not have IP or ARP layer
        # Skip packet
        return None
    
    # Get the PCAP file corresponding to the destination IP address
    other_pcap = maps_addr_pcap[protocol].get(dst, None)
    if other_pcap is None:
        return "wan.pcap"
    else:
        return other_pcap
    

def is_duplicate(packet: dict, idx: int, packets: list) -> bool:
    """
    Check if the given packet is a duplicate of the previous one.

    :param packet: given packet
    :param idx: packet index
    :param packets: list of packets
    :return: True if the packet is a duplicate of the previous one, False otherwise
    """
    return packet["is_initial"] and idx > 0 and packet["hash"] == packets[idx - 1]["hash"]


def read_packets_from_pcap(pcap_name: str, pcap_path: str, maps_addr_pcap: dict) -> Tuple[list, list]:
    """
    Read packets from a PCAP file,
    compute their hashes and store them in a list.

    :param pcap_name: name of the PCAP file
    :param pcap_path: full path to the PCAP file
    :param maps_addr_pcap: dictionary mapping addresses (MAC, IPv4 and IPv6) to PCAP files
    :return: list of packets and list of timestamps
    """
    packets = []
    timestamps = []
    pcap_idx = 1
    list_idx = 0
    raw_packets = scapy.rdpcap(pcap_path)
    for packet in raw_packets:

        # Dictionary containing packet information
        timestamp = float(packet.time)
        packet_dict = {
            "pcap_idx": pcap_idx,
            "hash": get_packet_hash(packet),
            "timestamp": timestamp,
            "packet": packet,
            "is_initial": False
        }

        # Get packet source and destination addresses
        if packet.haslayer(scapy.IP):
            # Packet has an IP layer
            layer = packet.getlayer(scapy.IP)
            protocol = f"ipv{layer.version}"
            src = layer.src
            dst = layer.dst
        elif packet.haslayer(scapy.ARP):
            # Packet has an ARP layer
            layer = packet.getlayer(scapy.ARP)
            protocol = "ipv4"
            src = layer.psrc
            dst = layer.pdst
        else:
            # Packet does not have IP or ARP layer
            # Skip packet
            pcap_idx += 1
            continue

        # If packet source or destination address is well-known,
        # and its base PCAP is the current one,
        # compute packet hash and add it to resulting list.
        src_base_pcap = maps_addr_pcap[protocol].get(src, None)
        dst_base_pcap = maps_addr_pcap[protocol].get(dst, None)
        if src_base_pcap == pcap_name or dst_base_pcap == pcap_name:
            packet_dict["is_initial"] = src_base_pcap == pcap_name
            if not is_duplicate(packet_dict, list_idx, packets):
                # If packet is not a duplicate,
                # append it to list
                packets.append(packet_dict)
                timestamps.append(timestamp)
                list_idx += 1
        
        # If packet source or destination address is not known,
        # and the current PCAP is for the WAN,
        # compute packet hash and add it to resulting list.
        if (src_base_pcap is None or dst_base_pcap is None) and pcap_name == "wan.pcap":
            packet_dict["is_initial"] = src_base_pcap is None
            if not is_duplicate(packet_dict, list_idx, packets):
                # If packet is not a duplicate,
                # append it to list
                packets.append(packet_dict)
                timestamps.append(timestamp)
                list_idx += 1

        pcap_idx += 1

    return packets, timestamps



# Program entry point
if __name__ == "__main__":

    ### ARGUMENT PARSING ###
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Read packet timestamp differences from PCAP files."
    )
    # Optional argument: experimental scenario
    scenarios = {
        "base": os.path.join("latency-base", "with-firewall"),
        "proto": os.path.join("proto", "latency"),
        "stats": os.path.join("stats", "latency"),
        "inter-lan": os.path.join("interaction", "lan", "latency"),
        "inter-wan": os.path.join("interaction", "wan", "latency")
    }
    parser.add_argument("-s", "--scenario", type=str, choices=scenarios.keys(), help="experimental scenario to read packets from")
    args = parser.parse_args()

    if args.scenario is not None:
        all_dirs = [os.path.join(script_dir, scenarios[args.scenario])]

    # Mapping between device addresses and PCAP files
    maps_addr_pcap = {
        "mac":  get_map_addr_pcap("mac", device),
        "ipv4": get_map_addr_pcap("ipv4", device),
        "ipv6": get_map_addr_pcap("ipv6", device)
    }


    ### MAIN PROGRAM ###

    # Iterate on all experimental scenarios
    for scenario_dir in all_dirs:

        ## Preprocessing
        # Compute hash values for each packet in each PCAP file
        packets = {}
        timestamps = {}
        for pcap in all_pcaps:
            pcap_path = os.path.join(scenario_dir, pcap)
            packets[pcap], timestamps[pcap] = read_packets_from_pcap(pcap, pcap_path, maps_addr_pcap)

        # Initialize CSV result file
        result_file_path = os.path.join(scenario_dir, "latency.csv")
        with open(result_file_path, "w") as f:
            fieldnames = ["hash", "base_pcap", "base_id", "base_packet", "base_timestamp", "other_pcap", "other_id", "other_packet", "other_timestamp", "latency"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            csv_packets = {}  # Resulting dict, will be populated by parsing

            # Iterate on PCAP files
            for pcap in all_pcaps:

                # Iterate on packets
                for packet in packets[pcap]:

                    # If packet is not initial, skip it
                    if not packet["is_initial"]:
                        continue

                    result_dict = {
                        "hash": packet["hash"],
                        "base_pcap": pcap,
                        "base_id": packet["pcap_idx"],
                        "base_packet": packet["packet"],
                        "base_timestamp": packet["timestamp"]
                    }
                    
                    # Get other PCAP to search for the corresponding packet
                    other_pcap = get_other_pcap(packet["packet"], maps_addr_pcap)
                    if other_pcap is not None:
                        # Search other PCAP for a matching packet
                        other_pcap_path = os.path.join(scenario_dir, other_pcap)
                        other_packet = search_packet(packets[other_pcap], timestamps[other_pcap], packet["timestamp"], packet["hash"])
                        if other_packet is not None and not other_packet["is_initial"]:
                            # Corresponding packet was found
                            
                            # Get old and new latency
                            old_latency = other_packet.get("latency", float("inf"))
                            new_latency = abs(packet["timestamp"] - other_packet["timestamp"])

                            if new_latency <= old_latency:

                                # Build dictionary containing packet data
                                other_packet["latency"] = new_latency
                                result_dict["other_pcap"] = other_pcap
                                result_dict["other_id"] = other_packet["pcap_idx"]
                                result_dict["other_packet"] = other_packet["packet"]
                                other_timestamp = other_packet["timestamp"]
                                result_dict["other_timestamp"] = other_timestamp
                                result_dict["latency"] = new_latency

                                # Remove old entry from CSV dict
                                old_key = (packet["hash"], old_latency)
                                csv_packets.pop(old_key, None)

                                # Add new entry to CSV dict
                                new_key = (packet["hash"], new_latency)
                                csv_packets[new_key] = result_dict
        
            writer.writerows(csv_packets.values())
        
        print(f"Result file written to {result_file_path}.")
