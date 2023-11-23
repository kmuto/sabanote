#!/bin/bash
COMMAND="ps axch o %cpu,%mem,time,command --sort -%cpu | head -n 20"

if [ -z "$MACKEREL_APIKEY" ]; then
  echo "Set MACKEREL_APIKEY as environment variable."
  exit 1
fi

HOSTS="aaaaa,bbbb,ccccc"
echo $HOSTS | tr ',' '\n' | while read line; do
  echo $line
done

#$(mkr alerts list )

exit 0
TITLE="processes at $(hostname)"
# write the status of processes is sorted by CPU
RESULT=$(eval $COMMAND)

RSIZE=$(echo "$RESULT" | wc -c | cut -d " " -f1)
if [ $RSIZE -ge 1023 ]; then
  RESULT=$(echo "$RESULT" | head -c 1023)
fi

FROM=$(date +"%s")
TO=$(expr $FROM + 59)
SERVICE=testservice
ROLE=elemental

echo "$RESULT"
#echo "$RESULT" | mkr annotations create --title "$TITLE" --description-file "-" --from $FROM --to $TO --service $SERVICE --role $ROLE 2>&1 >/dev/null
