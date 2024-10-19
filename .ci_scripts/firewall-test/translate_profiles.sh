# NFQueue start index
NFQ_ID_START=0

for DEVICE in devices/*
do
    if [ -d $DEVICE ]
    then
        python3 "src/translator/translator.py" "$DEVICE/profile.yaml" $NFQ_ID_START
        NFQ_ID_START=$((NFQ_ID_START+1000))
    fi
done
