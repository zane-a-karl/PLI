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
if [[ $# -lt 1 ]];
then
    echo "Error: Insufficient arguments provided";
    echo "Usage ./$0 <security parameter>";
    exit 1;
fi

# Global variables
client_file="input/client.txt"
server_file="input/server.txt"
start_size=10
end_size=100
sample_size=5
sec_par=$1
logfile="logs/elgamal-mh-$sec_par.csv"

echo "START AVERAGE RUNTIME/BANDWIDTH TEST";
echo "sec par, # entries, total bytes, total_time" > "$logfile";
for ((i=$start_size; i<=$end_size; i+=10))
do
    ./scripts/setup_input_files $i
    for ((j=0; j<$sample_size; j++))
    do
	make --quiet clean;
	make --quiet;
	printf "%s%d\n" "Begin:  Elgamal MH PLI Protocol #" "$j"
	./bin/client-and-server "localhost" "EG" "MH" "$sec_par" input/server.txt input/client.txt
	#	$pids=$(ps aux | grep "elgamal" | grep -v "grep" | awk '{print $2}')
	wait
	printf "%s%d\n\n" "Finish:  Elgamal MH PLI Protocol #" "$j"
    done
    echo "-------------------------------------------" >> "$logfile";
done
echo "END AVERAGE RUNTIME/BANDWIDTH TEST";