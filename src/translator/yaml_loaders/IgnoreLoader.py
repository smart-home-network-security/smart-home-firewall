"""
PyYAML loader which ignores tags.
Adapted from https://stackoverflow.com/questions/33048540/pyyaml-safe-load-how-to-ignore-local-tags.
"""

import yaml


class IgnoreLoader(yaml.SafeLoader):
    """
    Custom PyYAML loader, which ignores tags.
    """
    def __init__(self, stream) -> None:
        # Use parent constructor
        super().__init__(stream)


def construct_ignore(loader: IgnoreLoader, tag_suffix: str, node: yaml.Node) -> None:
    """
    PyYAML constructor which ignores tags.

    :param loader: PyYAML IgnoreLoader
    :param tag_suffix: YAML tag suffix
    :param node: YAML node, i.e. the value occurring after the tag
    """
    return None


# Add custom constructor
yaml.add_multi_constructor("!", construct_ignore, IgnoreLoader)
