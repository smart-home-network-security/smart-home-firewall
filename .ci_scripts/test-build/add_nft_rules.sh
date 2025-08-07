EXITCODE=0

# Ensure globbing expands to an empty list if no matches are found
shopt -s nullglob

for nft_script in devices/*/firewall*.nft
do
    # Try adding the ruleset
    sudo nft -f "$nft_script"
    # If the exit code is not 0, set EXITCODE to 1
    if [[ $? -ne 0 ]]
    then
        EXITCODE=1
    fi
    # Flush the ruleset before next device
    sudo nft flush ruleset
done

exit $EXITCODE
