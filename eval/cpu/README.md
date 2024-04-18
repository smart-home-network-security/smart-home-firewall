# Evaluation: CPU and memory usage

Plot CPU and memory usage,
for 4 different scenarios of system usage:
- **Normal**: Normal operation
- **State**: Under a steady flow of packets rejected by NFQueue because of the FSM state. The firewall must only check the FSM state to issue the reject verdict.
- **String**: Under a steady flow of DNS requests with an unexpected domain name. The firewall must perform name comparisons to issue the reject verdict.
- **Lookup**: Under a steady flow of packets directed towards an IP address not present in the DNS table. The firewall must perform a lookup in the DNS cache to issue the reject verdict.


### Plot

Read data from the PCAP files, and save them in CSV files with:
```bash
python3 read_each.py
```

Plot latency data with:
```bash
python3 plot.py [-f file_name]
```
with the following options:
- `file_name`: name of the file to save the graph to.
If not specified, the graph is shown on screen.
