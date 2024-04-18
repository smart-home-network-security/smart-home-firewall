# Evaluation: precision and accuracy

Please first make sure the system has been built with logging enabled.
Uncomment line 28 from the [root CMakeLists.txt](../../CMakeLists.txt),
which reads
```cmake
add_compile_options(-Wall -Werror -Wno-unused-variable -O3 -DLOG)
```
then build the system again.

Start Vagrant VM which will run the firewall:
```bash
vagrant up
```

Retrieve Vagrant VM SSH configuration:
```bash
vagrant ssh-config > vagrant-ssh-config
```

Retrieve Vagrant VM MAC address:
```bash
ssh -F vagrant-ssh-config default "ip link show enp0s8"
```

Produce ground truth data:
```bash
python3 ground_truth/ground-truth.py vm VAGRANT_VM_MAC
python3 ground_truth/merge-logs.py
```

Generate edited PCAP files:
```bash
python3 edited/generate-edited-pcaps.py
```

Replay each PCAP firewall through the router on which the firewall is running:
```bash
python3 edited/replay-edited-pcaps.py vm VAGRANT_VM_MAC
```

Process data, and plot confusion matrix:
```bash
python3 edited/merge-logs.py
python3 edited/link-interactions.py
python3 edited/plot.py
```
