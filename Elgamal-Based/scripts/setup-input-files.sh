#!/bin/bash

# Check sufficient arguments
if [[ $# -ne 2 ]]; then
    echo "Error: Insufficient arguments provided";
    echo "Usage $0 <list length> <security parameter>";
    exit 1;
fi
len=$1
secpar_val="2^$2"

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
matches=0
val=0
for ((k=0; k<$len; k++))
do
    val=$(echo "$k + $secpar_val" | bc)
    echo -n "$val" >> "$client_file";    
    if [[ $(($RANDOM%2)) -eq 0 ]];    
    then
	rand_val=$(echo "$((RANDOM%$len + $len + 1)) + $secpar_val" | bc)
	echo -n "$rand_val" >> "$server_file";
    else
	echo -n "$val" >> "$server_file";
	((matches++))
    fi

    # Add entry formatting
    if [[ $k -ne $(($len - 1)) ]];
    then
	echo -n ", " >> $client_file;
	echo -n ", " >> $server_file;
    else
	echo -n "]" >> $client_file;
	echo -n "]" >> $server_file;
    fi
done

echo "#########"
echo "$matches Matches"
echo "#########"

tmp_file="input/tmp.txt"
# Remove '\'s
awk '{ gsub(/\\/, "") } 1' $client_file > $tmp_file && mv $tmp_file $client_file
awk '{ gsub(/\\/, "") } 1' $server_file > $tmp_file && mv $tmp_file $server_file
# Remove '\n's
awk '{ printf "%s", $0 } END { print "" }' $client_file > $tmp_file && mv $tmp_file $client_file
awk '{ printf "%s", $0 } END { print "" }' $server_file > $tmp_file && mv $tmp_file $server_file