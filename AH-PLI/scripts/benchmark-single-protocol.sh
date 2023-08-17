#!/bin/bash

CUR_DIR=$(pwd | awk -F '/' '{print $NF}')
if [[ $CUR_DIR != "AH-PLI" ]];
then
    echo "You are in the wrong directory"
    echo "Please navigate to AH-PLI/"
    exit 1
fi

source ./scripts/helpers.sh

# Check sufficient arguments
if [[ $# -ne 4 ]]; then
    echo "Error: Insufficient arguments provided";
    echo "Usage $0 <pli method> <elgamal flavor> <homomorphism type> <security parameter>";
    exit 1;
fi

# Global variables
client_file="input/client.txt"
server_file="input/server.txt"
tmp_file="input/tmp.txt"
start_size=10
end_size=100
sample_size=10
pmeth=$(echo "$1" | to_lower | beautify_pmeth);
eflav=$(echo "$2" | to_upper | beautify_eflav);
htype=$(to_upper "$3");
secpar="$4"

if [[ "${eflav:0:1}" != "e" ]] || [[ "${htype: -1}" != "H" ]] || ! [[ "$secpar" =~ ^[0-9]*$ ]]; then
    echo "Input arguements are out of order"
    exit
fi

logfile="logs/$pmeth-$eflav-$htype-$secpar.csv"
# echo "$logfile"
# exit

make --quiet clean;
make --quiet;

echo "START AVERAGE RUNTIME/BANDWIDTH TEST";
echo "sec par, # entries, total bytes, total_time" > "$logfile";
for ((i=$start_size; i<=$end_size; i+=10))
do
    ./scripts/setup-input-files.sh $i $secpar
    # Remove '\'s
    awk '{ gsub(/\\/, "") } 1' $client_file > $tmp_file && mv $tmp_file $client_file
    awk '{ gsub(/\\/, "") } 1' $server_file > $tmp_file && mv $tmp_file $server_file
    # Remove '\n's
    awk '{ printf "%s", $0 } END { print "" }' $client_file > $tmp_file && mv $tmp_file $client_file
    awk '{ printf "%s", $0 } END { print "" }' $server_file > $tmp_file && mv $tmp_file $server_file

    for ((j=0; j<$sample_size; j++))
    do
	printf "%s%d\n" "Begin: $pmeth $eflav $htype Protocol #" "$j"
	./bin/main/client-and-server "localhost" "$pmeth" "$secpar" "$server_file" "$client_file" "$eflav" "$htype"
	#	$pids=$(ps aux | grep "elgamal" | grep -v "grep" | awk '{print $2}')
	wait
	printf "%s%d\n\n" "Finish:  $pmeth $eflav $htype Protocol #" "$j"
    done
    echo "-------------------------------------------" >> "$logfile";
done
echo "END AVERAGE RUNTIME/BANDWIDTH TEST";
