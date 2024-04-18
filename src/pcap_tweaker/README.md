# pcap-tweaker
This program randomly edits packets from a PCAP file,
one field per edited packet.

The edited field will be chosen at random,
starting from the highest layer, and going down until it finds a supported protocol layer.

Example: a DNS packet will have one of its DNS fields edited,
and not one of the UDP or IP fields.


## Dependencies

* [Scapy](https://scapy.net/)
  * `pip install scapy`

Install all with:
```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 pcap_tweaker.py [-h] [-o OUTPUT] [-r RANDOM_RANGE] [-n PACKET_NUMBER] [-d] pcap [pcap ...]
```

The program produces new PCAP file with the same name as the input files,
but with the suffix `.edit`.
The output files will be placed in a directory called `edited`,
in the same directory as the input files.
It will be created if it doesn't exist.

The program also produces CSV log files,
indicating which fields were edited for each packet.
The log files will be placed in a directory called `logs`,
in the same directory as the input files.
It will be created if it doesn't exist.

### Positional arguments

* `pcap`: PCAP file(s) to edit

### Optional arguments

* `-h`, `--help`: show help message and exit
* `-o`, `--output`: output PCAP (and CSV) file path. Used only if a single input file is specified. Default: `edited/<input_pcap>.edit.pcap`
* `-r`, `--random-range`: upper bound for the random range, which will select for each packet if it will be edited or not. In practice, each packet will be edited with a probability of `1/r`. Must be a strictly positive integer. Default: `1` (edit all packets).
* `-n`, `--packet-number`: index of the packet to edit, starting from 1. Can be specified multiple times. If this is used, only the specified packets will be edited, and no random editing will be performed.
* `-d`, `--dry-run`: don't write the output PCAP file (but still write the CSV log file)


## Supported protocols

* Datalink Layer (2)
  * ARP
* Network Layer (3)
  * IPv4
  * IPv6
* Transport Layer (4)
  * TCP
  * UDP
  * ICMP
  * IGMP(v2 and v3)
* Application Layer (7)
  * HTTP
  * DNS
  * DHCP
  * SSDP
  * CoAP
