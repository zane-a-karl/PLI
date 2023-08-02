#!/bin/bash

#NOTE: run script with list entries length as input

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
for ((k=1; k<$1; k++))
do
    if [[ $k -gt $(($1/2)) ]];
    then
	echo -n "$k, " >> "$client_file";
	rand_val=$((RANDOM%$1 + $1 + 1))
	echo -n "$rand_val, " >> "$server_file";
    else
	echo -n "$k, " >> "$client_file";
	echo -n "$k, " >> "$server_file";
    fi
done
echo "$1]" >> "$client_file";
echo "$((RANDOM%$1 + $1 + 1))]" >> "$server_file";
