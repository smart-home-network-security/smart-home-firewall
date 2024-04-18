"""
PyYAML loader which supports inclusion of external members.
Adapted from https://gist.github.com/joshbode/569627ced3076931b02f.
"""

import sys
import os
import yaml
import collections.abc

# Import IgnoreLoader
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from IgnoreLoader import IgnoreLoader


class IncludeLoader(yaml.SafeLoader):
    """
    Custom PyYAML loader, which supports inclusion of members defined in other YAML files.
    """
    def __init__(self, stream) -> None:
        # Use parent constructor
        super().__init__(stream)


def update_dict_aux(d: dict, key: str, parent_key: str, current_parent_key: str, old_val: str, new_val: str) -> None:
    """
    Helper recursive function for `update_dict`.

    :param d: dictionary to update
    :param key: key to update the value of
    :param parent_key: parent key of `key`
    :param current_parent_key: current parent key
    :param old_val: value to replace
    :param new_val: value to replace with
    """
    for k, v in d.items():
        if isinstance(v, collections.abc.Mapping):
            # Value is a dictionary itself, recursion time
            update_dict_aux(d.get(k, {}), key, parent_key, k, old_val, new_val)
        else:
            # Value is a scalar
            if k == key and current_parent_key == parent_key and v == old_val:
                d[k] = new_val


def update_dict(d: dict, key: str, parent_key: str, old_val: str, new_val: str) -> None:
    """
    Recursively update all occurrences of value `old_val`,
    which are nested under key `key` and parent key `parent_key`,
    with `new_val` in dictionary `d`.

    :param d: dictionary to update
    :param key: key to update the value of
    :param parent_key: parent key of `key`
    :param old_val: value to replace
    :param new_val: value to replace with
    """
    update_dict_aux(d, key, parent_key, "", old_val, new_val)


def replace_self_addrs(d: dict, mac: str = "", ipv4: str = "", ipv6: str = "") -> None:
    """
    Replace all occurrences of "self" with the given addresses.

    :param d: dictionary to update
    :param mac (optional): MAC address to replace "self" with
    :param ipv4 (optional): IPv4 address to replace "self" with
    :param ipv6 (optional): IPv6 address to replace "self" with
    """
    if mac:
        update_dict(d, "sha", "arp", "self", mac)
        update_dict(d, "tha", "arp", "self", mac)
    if ipv4:
        update_dict(d, "src", "ipv4", "self", ipv4)
        update_dict(d, "dst", "ipv4", "self", ipv4)
    if ipv6:
        update_dict(d, "src", "ipv6", "self", ipv6)
        update_dict(d, "dst", "ipv6", "self", ipv6)


def construct_include(loader: IncludeLoader, node: yaml.Node) -> dict:
    """
    Include member defined in another YAML file.

    :param loader: PyYAML IncludeLoader
    :param node: YAML node, i.e. the value occurring after the tag
    :return: included pattern (from this or another YAML profile)
    """
    scalar = loader.construct_scalar(node)
    
    # Split profile and values
    split1 = scalar.split(" ")
    profile = split1[0]
    values = split1[1:]

    # Parse values into dictionary
    values_dict = {}
    for value in values:
        split_value = value.split(":")
        if len(split_value) == 2:
            values_dict[split_value[0]] = split_value[1]

    # Split path and pattern from profile
    split2 = profile.split('#')
    path = os.path.abspath(loader.stream.name)  # Default path, the current profile
    if len(split2) == 1:
        members = split2[0]
    elif len(split2) == 2:
        if split2[0] != "self":
            path = os.path.join(os.path.dirname(path), split2[0])
        members = split2[1]

    # Load member to include
    addrs = {}
    data = {}
    with open(path, 'r') as f:
        data = yaml.load(f, IgnoreLoader)

        # Populate addrs
        addrs["mac"] = data["device-info"].get("mac", "")
        addrs["ipv4"] = data["device-info"].get("ipv4", "")
        addrs["ipv6"] = data["device-info"].get("ipv6", "")

        for member in members.split('.'):
            data = data[member]
    
    # Populate values
    data_top = data
    for key, value in values_dict.items():
        data = data_top
        split_key = key.split('.')
        i = 0
        for sub_key in split_key:
            if i == len(split_key) - 1:
                data[sub_key] = value
            else:
                data = data[sub_key]
                i += 1
    
    # Replace "self" with actual addresses
    if isinstance(data_top, collections.abc.Mapping):
        replace_self_addrs(data_top, addrs["mac"], addrs["ipv4"], addrs["ipv6"])
    
    return data_top


# Add custom constructor
yaml.add_constructor("!include", construct_include, IncludeLoader)
