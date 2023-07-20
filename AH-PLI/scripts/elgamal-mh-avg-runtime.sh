#!/bin/bash

# NOTE:
#     You must run this from the AH-PLI directory
CUR_DIR=$(pwd | awk -F '/' '{print $NF}')
if [[ $CUR_DIR != "AH-PLI" ]];
then
    echo "You are in the wrong directory"
    echo "Please navigate to AH-PLI/"
    exit 1
fi

# Global variables
client_file="input/client.txt"
server_file="input/server.txt"
start_size=10
end_size=100
sample_size=5
sec_par=2048
logfile="logs/elgamal-$sec_par.txt"

# Usage `setup_input_files $i`,
# where `i` is the current entry list size
function setup_input_files {
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

echo "START AVERAGE RUNTIME/BANDWIDTH TEST";
echo "sec par, \# entries, total bytes, total_time" > "$logfile";
for ((i=$start_size; i<=$end_size; i+=10))
do
    setup_input_files $i
    for ((j=0; j<$sample_size; j++))
    do
	make --quiet clean;
	make --quiet;
	printf "%s%d\n" "Begin:  Elgamal MH PLI Protocol #" "$j"
	./bin/elgamal-client-and-server localhost MH $sec_par input/server.txt input/client.txt
	#	$pids=$(ps aux | grep "elgamal" | grep -v "grep" | awk '{print $2}')
	wait
	printf "%s%d\n\n" "Finish:  Elgamal MH PLI Protocol #" "$j"
    done
    echo "-------------------------------------------" >> "$logfile";
done
echo "END AVERAGE RUNTIME/BANDWIDTH TEST";