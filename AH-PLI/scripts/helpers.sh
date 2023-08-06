#!/bin/bash

# List of helper functions to the benchmarking scripts

# Converts input string to lowercase
function to_lower {
    local input="$1"
    if [[ -z "$input" ]]; then read -r input; fi
    echo "$input" | tr '[:upper:]' '[:lower:]';
}

# Converts input string to uppercase
function to_upper {
    local input="$1"
    if [[ -z "$input" ]]; then read -r input; fi    
    echo "$input" | tr '[:lower:]' '[:upper:]';
}

# usage fn <str> idx_start idx_end
# idx_end is inclusive
# "hello world" 0 4 -> "HELLO world"
function substr_to_upper() {
    local input=$1
    local start=$2
    local end=$3

    # Get the substring from the input string
    local substring="${input:start:$((end - start + 1))}"

    # Convert the substring to uppercase using parameter expansion
    local uppercase_substring=$(echo "$substring" | tr '[:lower:]' '[:upper:]')

    # Replace the original substring in the input string with the uppercase version
    local modified_string="${input:0:start}${uppercase_substring}${input:$((end + 1))}"

    # Output the modified string
    echo "$modified_string"
}

# Makes the "pli" part of the string uppercase
function beautify_pmeth {
    local input="$1"
    if [[ -z "$input" ]]; then read -r input; fi
    local length=${#input}

    for ((i = 0; i < length - 2; i++)); do
        if [[ "${input:$i:3}" == "pli" ]]; then
            input=$(substr_to_upper "$input" $i $((i + 2)))
        fi
    done

    echo "$input"
}

# note: run script with list entries length as input
function setup_input_files {
    local client_file="input/client.txt"
    local server_file="input/server.txt"

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
}

# Converts "EG" -> "elgamal" and "ECEG" -> "ecelgamal"
function beautify_eflav {
    local input="$1"
    if [[ -z "$input" ]]; then read -r input; fi
    if [[ "$input" == "EG" || "$input" == "ELGAMAL" ]]; then
	echo "elgamal";
    elif [[ "$input" == "ECEG" || "$input" == "ECELGAMAL" ]]; then
	 echo "ecelgamal";
    else
	echo "Invalid elgamal flavor input"; exit;
    fi
}
