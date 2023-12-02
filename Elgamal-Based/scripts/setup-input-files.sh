#!/bin/bash

function setup_input_files {

    # Check sufficient arguments
    if [ $# -ne 6 ]; then
	echo "Error: Insufficient arguments provided";
	echo "Usage $0 -n <list length> -s <security parameter> -f <fraction matching>";
	echo "Note argument to '-f' must be a decimal"
	exit 1;
    fi

    # Defaults
    local len=10
    local secpar="2^64"
    # Using bc
    local fraction=$(echo "scale=2; 6/10" | bc)
    # Using awk
    # local fraction=$(awk "BEGIN {printf \"%.2f\",4/10}")

    # Have to use this weird shifting method to read input because
    # getopts command only works with scripts and not functions
    while [ $# -gt 0 ]; do
        case $1 in
            -n)
                len=$2
                shift 2
                ;;
            -s)
                secpar="2^$2"
                shift 2
                ;;
            -f)
                fraction=$(echo "scale=2; $2" | bc)
                shift 2
                ;;
            *)
                # Unknown option
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Global variables
    client_file="input/client.txt"
    server_file="input/server.txt"

    # if file exists delete it
    if [ -e "$client_file" ] || [ -e "$server_file" ];
    then
	rm $client_file $server_file
    fi

    local MAX_RANDOM=32767 # Max value of $RANDOM function
    local MATCH_CUTOFF=$(printf "%.0f" $(echo "$fraction * $MAX_RANDOM - ($fraction * $MAX_RANDOM % 10)" | bc))
    local matches=0
    local val=0
    local rand_val=0
    RANDOM=$MAX_RANDOM # apparently you need to seed it

    echo "Creating client and server input files"
    echo "fraction = $fraction"
    echo -n "[" > "$client_file";
    echo -n "[" > "$server_file";
    for ((k=0; k<$len; k++))
    do
	val=$(echo "$k + $secpar" | bc)
	echo -n "$val" >> "$client_file";
	if [ $RANDOM -ge $MATCH_CUTOFF ];
	then
	    rand_val=$(echo "$(($RANDOM % $len + $len + 1)) + $secpar" | bc)
	    echo -n "$rand_val" >> "$server_file";
	else
	    echo -n "$val" >> "$server_file";
	    ((matches++))
	fi

	# Add entry formatting
	if [ $k -ne $(($len - 1)) ];
	then
	    echo -n ", " >> $client_file;
	    echo -n ", " >> $server_file;
	else
	    echo -n "]" >> $client_file;
	    echo -n "]" >> $server_file;
	fi
    done

    tmp_file="input/tmp.txt"
    # Remove '\'s
    awk '{ gsub(/\\/, "") } 1' $client_file > $tmp_file && mv $tmp_file $client_file
    awk '{ gsub(/\\/, "") } 1' $server_file > $tmp_file && mv $tmp_file $server_file
    # Remove '\n's
    awk '{ printf "%s", $0 } END { print "" }' $client_file > $tmp_file && mv $tmp_file $client_file
    awk '{ printf "%s", $0 } END { print "" }' $server_file > $tmp_file && mv $tmp_file $server_file

    echo "#########"
    echo "$matches Matches"
    echo "#########"

    return $matches
}