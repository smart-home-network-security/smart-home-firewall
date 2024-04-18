# Evaluation: Latency in a real-world network

Plot, per device, the latency induced by the firewall,
in 4 experimental scenarios:
- **no-firewall**: Without any firewall.
- **base-firewall**: with the default built-in OpenWrt firewall rules active on the AP. These rules accept all packets, but introduce some rate limiting, e.g., for incoming TCP SYN packets.
- **my-firewall**: with our firewall. We only use one device at a time and activate only the profile for that device.  We repeat this for all devices.
- **all-devices**: with our firewall. All device profiles are activated, and we interact with the six devices at the same time to mimic a busy Smart Home network.


### Plot

Read data from the PCAP files, and save them in CSV files with:
```bash
python3 read_each.py
python3 read_all.py
```

Plot latency data with:
```bash
python3 plot_latency_per_scenario.py [-p plot_type] [-f file_name]
```
with the following options:
- `plot_type`:
  - `bar`: bar plot (default)
  - `box`: box plot
  - `violin`: violin plot
  - `scatter`: scatter plot
  - `point`: point plot
- `file_name`: name of the file to save the graph to.
If not specified, the graph is shown on screen.
