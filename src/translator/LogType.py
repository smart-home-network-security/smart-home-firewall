from enum import IntEnum

class LogType(IntEnum):
    """
    Enum class for the type of logging to be used.
    """
    NONE = 0  # No logging
    CSV  = 1  # Log to a CSV file
    PCAP = 2  # Log to a PCAP file

    def __str__(self):
        return self.name
