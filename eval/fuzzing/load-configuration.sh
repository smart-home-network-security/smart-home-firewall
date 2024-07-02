echo "Input device: $1"
sudo nft flush ruleset
echo "Flushing ruleset"
sudo nft -f ~/iot-firewall/devices/$1/firewall.nft
echo "Loading ruleset"
echo "Running NFQueue for $1"
sudo ~/iot-firewall/bin/$1
