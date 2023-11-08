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
