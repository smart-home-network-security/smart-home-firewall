from __future__ import annotations
from typing import Union
import importlib

class Protocol:
    """
    Generic protocol, inherited by all concrete protocols.
    """
    

    def __init__(self, protocol_data: dict, device: dict) -> None:
        """
        Generic protocol constructor.

        :param protocol_data: Dictionary containing the protocol data.
        :param device: Dictionary containing the device metadata.
        """
        self.protocol_data = protocol_data
        self.device = device
        self.rules = {
            "nft": [],
            "nfq": []
        }


    @staticmethod
    def convert_value(value: str) -> Union[str, int]:
        """
        Convert a string value to an int if possible.

        :param value: Value to convert.
        :return: Converted value as int if possible, or the original string value otherwise.
        """
        try:
            result = int(value)
        except ValueError:
            result = value
        return result


    @classmethod
    def init_protocol(c, protocol_name: str, protocol_data: dict, device: dict) -> Protocol:
        """
        Factory method for a specific protocol.

        :param protocol_name: Name of the protocol.
        :param protocol_data: Dictionary containing the protocol data.
        :param device: Dictionary containing the device metadata.
        """
        module = importlib.import_module(f"protocols.{protocol_name}")
        cls = getattr(module, protocol_name)
        return cls(protocol_data, device)

    
    def format_list(self, l: list, func = lambda x: x) -> str:
        """
        Format a list of values.

        :param l: List of values.
        :param func: Function to apply to each value.
                     Optional, default is the identity function.
        :return: Formatted list.
        """
        value = "{ "
        for i in range(len(l)):
            if i != 0:
                value += ", "
            value += str(func(l[i]))
        value += " }"
        return value

    
    def add_field(self, field: str, template_rules: dict, is_backward: bool = False, func = lambda x: x, backward_func = lambda x: x) -> None:
        """
        Add a new nftables rule to the nftables rules accumulator.

        :param field: Field to add the rule for.
        :param template_rules: Dictionary containing the protocol-specific rules to add.
        :param is_backward (optional): Whether the field to add is for a backward rule.
                                       Optional, default is `False`.
        :param func (optional): Function to apply to the field value before writing it.
                                Optional, default is the identity function.
        :param backward_func (optional): a to apply to the field value in the case of a backwards rule.
                                         Will be applied after the forward function.
                                         Optional, default is the identity function.
        Args:
            field (str): Field to add the rule for.
            rules (dict): Dictionary containing the protocol-specific rules to add.
            is_backward (bool): Whether the field to add is for a backward rule.
                                Optional, default is `False`.
            func (lambda): Function to apply to the field value before writing it.
                           Optional, default is the identity function.
            backward_func (lambda): a to apply to the field value in the case of a backwards rule.
                           Will be applied after the forward function.
                           Optional, default is the identity function.
        """
        if self.protocol_data is not None and field in self.protocol_data:
            value = self.protocol_data[field]

            # If value from YAML profile is a list, add each element
            if type(value) == list:
                # Value is a list
                value = self.format_list(value, func)
            else:
                # Value is a single element
                value = func(value)

            # Build rule
            rule = {}
            value = Protocol.convert_value(value)
            if not is_backward:
                rule = {"template": template_rules["forward"], "match": value}
            elif is_backward and "backward" in template_rules:
                rule = {"template": template_rules["backward"], "match": backward_func(value)}

            # Add rule to the list of rules
            if rule:
                self.rules["nft"].append(rule)


    def parse(self, is_backward: bool = False, initiator: str = "src") -> dict:
        """
        Default parsing method.
        Must be updated in the children class.

        :param is_backward (optional): Whether the protocol must be parsed for a backward rule.
                                       Optional, default is `False`.
        :param initiator (optional): Connection initiator (src or dst).
                                    Optional, default is "src".
        :return: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        return self.rules
