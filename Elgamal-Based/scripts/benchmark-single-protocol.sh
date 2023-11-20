#!/bin/bash

CUR_DIR=$(pwd | awk -F '/' '{print $NF}')
if [[ $CUR_DIR != "Elgamal-Based" ]];
then
    echo "You are in the wrong directory"
    echo "Please navigate to Elgamal-Based/"
    exit 1
fi

source ./scripts/helpers.sh

# Global variable defaults
client_file="input/client.txt"
server_file="input/server.txt"
tmp_file="input/tmp.txt"
start_size=10
end_size=100
sample_size=5
pmeth="PLI"
eflav="ECEG"
htype="AH"
secpar=224
list_len=10
thresh=3

# Use getopts to handle argument input more cleanly
while getopts "p:e:m:y:n:t:" opt; do
    case $opt in
	p)
	    echo "Option 'p' was triggered with argument: $OPTARG"
	    pmeth=$OPTARG
	    ;;
	e)
	    echo "Option 'e' was triggered with argument: $OPTARG"
	    eflav=$OPTARG
	    ;;
	m)
	    echo "Option 'm' was triggered with argument: $OPTARG"
	    htype=$OPTARG
	    ;;
	y)
	    echo "Option 'y' was triggered with argument: $OPTARG"
	    secpar=$OPTARG
	    ;;
	n)
	    # Kind of useless at the moment because this doesn't affect anything
	    echo "Option 'd' was triggered with argument: $OPTARG"
	    list_len=$OPTARG;
	    ;;
	t)
	    # Kind of useless at the moment because this doesn't affect anything
	    echo "Option 'd' was triggered with argument: $OPTARG"
	    thresh=$OPTARG
	    ;;
	\?)
	    # Invalid option
	    echo "Invalid option: -$OPTARG"
	    exit 1
	    ;;
    esac
done

# After processing options, you can access non-option arguments (e.g., filenames) like this:
shift $((OPTIND - 1))
echo "Non-option arguments: $@"

pmeth=$(echo "$pmeth" | to_lower | beautify_pmeth);
eflav=$(echo "$eflav" | to_upper | beautify_eflav);
htype=$(to_upper "$htype");

logfile="logs/$pmeth-$eflav-$htype-$secpar.csv"
echo "$logfile"

make --quiet clean;
make --quiet;

echo "START AVERAGE RUNTIME/BANDWIDTH TEST";
echo "sec par, # entries, total bytes, total_time" > "$logfile";
for ((i=$start_size; i<=$end_size; i+=$sample_size))
do

    for ((j=0; j<$sample_size; j++))
    do
	./scripts/setup-input-files.sh $i $secpar
	# Remove '\'s
	awk '{ gsub(/\\/, "") } 1' $client_file > $tmp_file && mv $tmp_file $client_file
	awk '{ gsub(/\\/, "") } 1' $server_file > $tmp_file && mv $tmp_file $server_file
	# Remove '\n's
	awk '{ printf "%s", $0 } END { print "" }' $client_file > $tmp_file && mv $tmp_file $client_file
	awk '{ printf "%s", $0 } END { print "" }' $server_file > $tmp_file && mv $tmp_file $server_file


	printf "%s%d\n" "Begin: $pmeth $eflav $htype Protocol #" "$j"
	# exit
	./bin/main/client-and-server -p "$pmeth" -y "$secpar" -e "$eflav" -m "$htype" -t "$(($i/3))"
	#	$pids=$(ps aux | grep "elgamal" | grep -v "grep" | awk '{print $2}')
	wait
	printf "%s%d\n\n" "Finish:  $pmeth $eflav $htype Protocol #" "$j"
    done
    echo "-------------------------------------------" >> "$logfile";
done
echo "END AVERAGE RUNTIME/BANDWIDTH TEST";
