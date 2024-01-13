#!/bin/bash

# Enable uninitialized variable checking
set -u

function accumulate_averages {

    # Check sufficient arguments
    if [ $# -ne 2 ]; then
	echo "Error: Insufficient arguments provided";
	echo "Usage $0 -f <log filename>";
	exit 1;
    fi

    local log_filename="";

    # Have to use this weird shifting method to read input because
    # getopts command only works with scripts and not functions
    while [ $# -gt 0 ]; do
        case $1 in
            -f)
                log_filename=$2
                shift 2
                ;;
            *)
                # Unknown option
                echo "Unknown option: $1"
		exit 1;
                ;;
        esac
    done

    # if the log_filename doesn't exist exit
    if ! [ -f $log_filename ]; then
	echo "Error: filename \"$log_filename\" does not exist";
	exit 1;
    fi
    local output_filename="${log_filename%.*}-averages.csv"
    echo "The input file is : $log_filename"
    echo "The output file is: $output_filename"

    # If the file already exists backit up
    if [ -e "$output_filename" ];
    then
	mv "$output_filename" "${output_filename%.*}-$(date +%Y-%m-%d\[%H:%M\]).csv"
    fi
    # Grab the header line
    awk -F", " 'NR == 1 {print; next} /^[-]*$/ {next} { bytes_sum += $5; time_sum += $6; row_count++ } row_count == 10 { printf "%d, %d, %d, %d, ", $1, $2, $3, $4; printf "%d, ", bytes_sum/row_count; bytes_sum = 0; printf "%.6f%s", time_sum/row_count, "\n"; time_sum = 0; row_count = 0; }' "$log_filename" > "$output_filename"

}