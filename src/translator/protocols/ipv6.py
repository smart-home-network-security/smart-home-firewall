from protocols.ip import ip
from protocols.icmpv6 import icmpv6

class ipv6(ip):

    # Class variables
    protocol_name = "ipv6"  # Protocol name
    nft_prefix = "ip6"      # Prefix for nftables rules

    # Well-known addresses
    addrs = {
        **ip.addrs["ipv6"],
        **icmpv6.groups
    }
