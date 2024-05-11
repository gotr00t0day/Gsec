#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

output=$(curl -s "https://crt.sh/?o=$1&output=json" | jq -r '.[].common_name')

if [ -z "$output" ]; then
    echo "Error: No output received from crt.sh"
    exit 1
elif [[ "$output" == *"error"* ]]; then
    echo "Error: $output"
    exit 1
fi

domains=$(echo "$output" | sed 's/\*//g' | sort -u | rev | cut -d "." -f 1,2 | rev | sort -u)

echo "$domains"
