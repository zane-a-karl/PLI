#!/bin/bash

# Check sufficient arguments
if [[ $# -ne 2 ]]; then
    echo "Error: Insufficient arguments provided";
    echo "Usage $0 <list length> <security parameter>";
    exit 1;
fi
len=$1
secpar="2^$2"

# Global variables
client_file="input/client.txt"
server_file="input/server.txt"

# Usage `setup_input_files $i`,
# where `i` is the current entry list size
if [[ -e "$client_file" ]] || [[ -e "$server_file" ]];
then
    rm $client_file $server_file
fi
echo "Create client and server input files"
echo -n "[" > "$client_file";
echo -n "[" > "$server_file";
val=0
for ((k=0; k<$(($len-1)); k++))
do
    if [[ $k -gt $(($len/2 - 1)) ]];
    then
	val=$(echo "$k + $secpar" | bc)
	echo -n "$val, " >> "$client_file";
	rand_val=$(echo "$((RANDOM%$len + $len + 1)) + $secpar" | bc)
	echo -n "$rand_val, " >> "$server_file";
    else
	val=$(echo "$k + $secpar" | bc)
	echo -n "$val, " >> "$client_file";
	echo -n "$val, " >> "$server_file";
    fi
done
val=$(echo "$len - 1 + $secpar" | bc)
rand_val=$(echo "$((RANDOM%$len + $len + 1)) + $secpar" | bc)
echo "$val]" >> "$client_file";
echo "$rand_val]" >> "$server_file";
