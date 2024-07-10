from protocols.Transport import Transport

class tcp(Transport):
    
    # Class variables
    protocol_name = "tcp"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = Transport.supported_keys + ["initiated-by"]
