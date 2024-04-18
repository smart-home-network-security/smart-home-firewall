# Evaluation: Latency under attacks

Plot latency induced by the firewall,
when undergoing 4 attack scenarios.


### Plot

Read data from the PCAP files, and save them in CSV files with:
```bash
python3 read_each.py
```

Plot latency data with:
```bash
python3 plot.py [-p plot_type] [-f file_name]
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
