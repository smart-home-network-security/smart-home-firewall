from protocols.Protocol import Protocol

class Custom(Protocol):

    # Class variables
    custom_parser = True  # Whether the protocol has a custom parser


    @staticmethod
    def build_nfq_list_match(l: list, template_rules: dict, is_backward: bool = False, func = lambda x: x, backward_func = lambda x: x) -> dict:
        """
        Produce a nfqueue match for a list of values.

        :param l: List of values.
        :param template_rules: Dictionary containing the protocol-specific rules to add.
        :param is_backward: Whether the field to add is for a backward rule.
        :param func: Function to apply to the field value before writing it.
                     Optional, default is the identity function.
        :param backward_func: Function to apply to the field value in the case of a backwards rule.
                              Will be applied after `func`.
                              Optional, default is the identity function.
        """
        template = []
        match = []
        # Value is a list
        for v in l:
            if not is_backward:
                template.append(template_rules["forward"])
                match.append(func(v))
            elif is_backward and "backward" in template_rules:
                template.append(template_rules["backward"])
                match.append(backward_func(func(v)))
        return {"template": template, "match": match}


    def add_field(self, field: str, template_rules: dict, is_backward: bool = False, func = lambda x: x, backward_func = lambda x: x) -> None:
        """
        Add a new nfqueue match to the accumulator.
        Overrides the nftables version.

        :param field: Field to add the rule for.
        :param template_rules: Dictionary containing the protocol-specific rules to add.
        :param is_backward: Whether the field to add is for a backward rule.
        :param func: Function to apply to the field value before writing it.
                     Optional, default is the identity function.
        :param backward_func: Function to apply to the field value in the case of a backwards rule.
                              Will be applied after `func`.
                              Optional, default is the identity function.
        Args:
            field (str): Field to add the rule for.
            template_rules (dict): Dictionary containing the protocol-specific rules to add.
            is_backward (bool): Whether the field to add is for a backward rule.
            func (lambda): Function to apply to the field value before writing it.
                           Optional, default is the identity function.
            backward_func (lambda): Function to apply to the field value in the case of a backwards rule.
                           Will be applied after `func`.
                           Optional, default is the identity function.
        """
        if field in self.protocol_data:
            value = self.protocol_data[field]
            rules = {}

            # If value from YAML profile is a list, produce disjunction of all elements
            if type(value) == list:
                rules = Custom.build_nfq_list_match(value, template_rules, is_backward, func, backward_func)
            else:
                # Value is a single element
                value = Protocol.convert_value(value)
                if not is_backward:
                    rules = {"template": template_rules["forward"], "match": func(value)}
                elif is_backward and "backward" in template_rules:
                    rules = {"template": template_rules["backward"], "match": backward_func(func(value))}

            # Append rules
            if rules:
                self.rules["nfq"].append(rules)
