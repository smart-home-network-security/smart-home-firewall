#!/usr/bin/python3

import os
from pathlib import Path
import argparse
from bisect import bisect
import hashlib
import csv
import ipaddress
import scapy.all as scapy
from typing import Tuple
from enum import Enum


### GLOBAL VARIABLES ###
ETH_HEADER_SIZE = 14
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
all_pcaps = [
    "lan.pcap",
    "wlan2.4.pcap",
    "wlan5.0.pcap",
    "wan.pcap"
]

smartthings_data = {
    "pcap": "lan.pcap",
    "mac":  "68:3a:48:13:27:04",
    "ipv4": "192.168.1.223",
    "ipv6": "fdb9:136b:cd34:e86f:6a3a:48ff:fe13:2704"
}
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
    "smartthings-hub": smartthings_data,
    #"smartthings-door": smartthings_data,
    #"smartthings-motion": smartthings_data,
    #"smartthings-presence": smartthings_data,
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

# Protocol categories for grouping
class ProtocolCategory(Enum):
    A = 0
    B = 1
    C = 2
    D = 3

protocol_categories = {
    # Category A: NFTables only matches
    "TCP":   ProtocolCategory.A,
    "UDP":   ProtocolCategory.A,
    "ICMP":  ProtocolCategory.A,
    "ARP":   ProtocolCategory.A,
    # Category B: NFQueue string comparison
    "DNS":   ProtocolCategory.B,
    "DHCP":  ProtocolCategory.B,
    "IGMP":  ProtocolCategory.B,
    "SSDP":  ProtocolCategory.B,
    "CoAP":  ProtocolCategory.B,
    # Category C: domain name lookup
    "HTTPS": ProtocolCategory.C,
    "NTP":   ProtocolCategory.C,
    "STUN":  ProtocolCategory.C,
    # Category D: domain name lookup + string comparison
    "HTTP":  ProtocolCategory.D
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


def get_packet_size(packet: scapy.Packet) -> int:
    """
    Get the full size of a Scapy packet, in bytes,
    not considering potential packet truncation.

    :param packet: Scapy Packet
    :return: packet length
    """
    if packet.haslayer(scapy.IP):
        # Packet has an IP layer
        # Get IP layer length
        return ETH_HEADER_SIZE + packet.getlayer(scapy.IP).len
    else:
        # Packet does not have an IP layer
        return len(packet)


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


def get_highest_protocol(packet: scapy.Packet) -> str:
    """
    Get the protocol of the highest layer a Scapy packet.

    :param packet: Scapy Packet
    :param device: device name
    :return: name of the highest layer's protocol
    """
    # Dummy names
    dummy_protocols = ["Raw", "Padding"]

    # Retrieve classic protocol name
    i = 0
    layer = packet.getlayer(i)
    while layer is not None and layer.name not in dummy_protocols:
        i += 1
        layer = packet.getlayer(i)
    protocol = packet.getlayer(i - 1).name

    ### Special cases ###

    # ICMP
    if "ICMP" in protocol:
        return "ICMP"
    
    # NTP
    if "NTP" in protocol:
        return "NTP"
    
    # UDP-based: SSDP, STUN
    if protocol == "UDP":
        sport = packet.getfieldval("sport")
        dport = packet.getfieldval("dport")
        if sport == 1900 or dport == 1900:
            return "SSDP"
        if sport == 3478 or dport == 3478:
            return "STUN"
        
    # HTTP(S)
    if protocol == "TCP":
        sport = packet.getfieldval("sport")
        dport = packet.getfieldval("dport")
        if sport == 80 or dport == 80:
            return "HTTP"
        if sport == 443 or dport == 443:
            return "HTTPS"

    # Default case
    protocol = protocol.split()[0]
    return protocol


def get_protocol_category(packet: scapy.Packet, device: str) -> ProtocolCategory:
    """
    Get the protocol category of a Scapy packet.
    The protocol category is defined as follows:
        - A: NFTables only matches
        - B: NFQueue string comparison
        - C: domain name lookup
        - D: domain name lookup and string comparison

    :param packet: Scapy Packet
    :param device: device name
    :return: protocol category
    """
    # Get highest layer protocol
    protocol = get_highest_protocol(packet)

    # Special case: tplink-plug NTP
    if device == "tplink-plug" and protocol == "NTP":
        return ProtocolCategory.A

    # Special case: xiaomi-cam UDP stream with cloud server
    if device == "xiaomi-cam" and protocol == "UDP":
        server_ip_a = "110.43.39.53"
        server_ip_b = "110.43.68.154"
        ip_src = packet.getlayer("IP").getfieldval("src")
        ip_dst = packet.getlayer("IP").getfieldval("dst")
        if ip_src == server_ip_a or ip_src == server_ip_b or ip_dst == server_ip_a or ip_dst == server_ip_b:
            return ProtocolCategory.B

    # Special case: HTTP(S)
    if "HTTP" in protocol:
        sport = packet.getfieldval("sport")
        server_is_src = sport == 80 or sport == 443
        if server_is_src:
            server_ip_addr = ipaddress.ip_address(packet.getlayer("IP").getfieldval("src"))
        else:
            server_ip_addr = ipaddress.ip_address(packet.getlayer("IP").getfieldval("dst"))
        lan = ipaddress.ip_network("192.168.0.0/16")
        if server_ip_addr in lan:
            if protocol == "HTTP":
                return ProtocolCategory.B
            elif protocol == "HTTPS":
                return ProtocolCategory.A

    # Default case
    return protocol_categories.get(protocol, ProtocolCategory.A)


# Program entry point
if __name__ == "__main__":

    ### ARGUMENT PARSING ###
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Read packet timestamp differences from PCAP files."
    )
    # Positional argument #1: IoT device under test
    help = "IoT device under test"
    parser.add_argument("device", type=str, choices=devices, help=help)
    # Positional argument #2: experimental scenario
    exps = ["no-firewall", "base-firewall", "my-firewall"]
    help = "Experimental scenario"
    parser.add_argument("scenario", type=str, choices=exps, help=help)
    # Parse arguments
    args = parser.parse_args()

    # Get working directory for the given device and scenario
    scenario_dir = os.path.join(script_dir, args.device, args.scenario)

    # Mapping between device addresses and PCAP files
    maps_addr_pcap = {
        "mac":  get_map_addr_pcap("mac", args.device),
        "ipv4": get_map_addr_pcap("ipv4", args.device),
        "ipv6": get_map_addr_pcap("ipv6", args.device)
    }


    ### MAIN PROGRAM ###

    ## Preprocessing
    # Compute hash values for each packet in each PCAP file
    packets = {}
    timestamps = {}
    for pcap in all_pcaps:
        pcap_path = os.path.join(scenario_dir, pcap)
        packets[pcap], timestamps[pcap] = read_packets_from_pcap(pcap, pcap_path, maps_addr_pcap)

    # Initialize CSV result file
    result_file_name = f"{args.device}_{args.scenario}.csv"
    result_file_path = os.path.join(scenario_dir, result_file_name)
    with open(result_file_path, "w") as f:
        fieldnames = ["hash", "base_pcap", "base_id", "base_timestamp", "other_pcap", "other_id", "other_timestamp",  "packet", "latency", "protocol_category", "packet_size"]
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
                    "packet": packet["packet"],
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
                            other_timestamp = other_packet["timestamp"]
                            result_dict["other_timestamp"] = other_timestamp
                            result_dict["latency"] = new_latency
                            result_dict["packet_size"] = get_packet_size(packet["packet"])

                            # Remove old entry from CSV dict
                            old_key = (packet["hash"], old_latency)
                            csv_packets.pop(old_key, None)

                            # Retrieve packet's highest protocol
                            result_dict["protocol_category"] = get_protocol_category(packet["packet"], args.device).name

                            # Add new entry to CSV dict
                            new_key = (packet["hash"], new_latency)
                            csv_packets[new_key] = result_dict
    
        writer.writerows(csv_packets.values())
    
    print(f"Result file written to {result_file_path}.")
