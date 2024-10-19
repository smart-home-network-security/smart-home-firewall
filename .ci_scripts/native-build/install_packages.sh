#!/bin/bash

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y gcc make cmake libcunit1 libcunit1-dev net-tools libjansson-dev libmnl-dev libnftnl-dev nftables libnftables-dev libnetfilter-queue-dev libnetfilter-log-dev valgrind cppcheck
