# Evaluation: Firewall code size metrics

Plot, per device,
the number of NFTables rules
and the number of lines of code (LoC)
for NFQueue C code.


### Plot

Read data from the PCAP files, and save them in CSV files with:
```bash
python3 read.py
```

Plot firewall size data with:
```bash
python3 plot.py [-f file_name]
```
with the following options:
- `file_name`: name of the file to save the graph to.
If not specified, the graph is shown on screen.
