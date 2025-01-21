#!/bin/bash

while IFS=', ' read -r SUBNAME SUBID 
do
    #You can do your processing here, e.g.
    echo "$SUBID $SUBNAME"
    python3 azurecliscript.py -c -s $SUBID -o $SUBNAME.json
done < azsubscription.txt 

exit 0
