echo "Input device: $1"
sudo nft flush ruleset
echo "Flushing ruleset"
sudo nft -f ~/smart-home-firewall/devices/$1/firewall.nft
echo "Loading ruleset"
echo "Running NFQueue for $1"
sudo ~/smart-home-firewall/bin/$1
