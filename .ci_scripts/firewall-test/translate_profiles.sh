# NFQueue start index
NFQ_ID_START=0

for DEVICE in $GITHUB_WORKSPACE/devices/*
do
    if [ -d $DEVICE ]
    then
        python3 "$GITHUB_WORKSPACE/src/translator/translator.py" "$DEVICE/profile.yaml" $NFQ_ID_START
        NFQ_ID_START=$((NFQ_ID_START+1000))
    fi
done
