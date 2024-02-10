#!/bin/bash

CUR_DIR=$(pwd | awk -F '/' '{print $NF}')
if [[ $CUR_DIR != "Elgamal-Based" ]];
then
    echo "You are in the wrong directory"
    echo "Please navigate to Elgamal-Based/"
    exit 1
fi

source ./scripts/helpers.sh
source ./scripts/setup-input-files.sh

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
min_thresh=1 # stands for 1/10
max_thresh=9 # stands for 9/10
min_percent=39 # stands for 39/10
max_percent=99 # stands for 99/10

# Use getopts to handle argument input more cleanly
while getopts "p:e:m:y:n:" opt; do
    case $opt in
	p)
	    # echo "Option 'p' was triggered with argument: $OPTARG"
	    pmeth=$OPTARG
	    ;;
	e)
	    # echo "Option 'e' was triggered with argument: $OPTARG"
	    eflav=$OPTARG
	    ;;
	m)
	    # echo "Option 'm' was triggered with argument: $OPTARG"
	    htype=$OPTARG
	    ;;
	y)
	    # echo "Option 'y' was triggered with argument: $OPTARG"
	    secpar=$OPTARG
	    ;;
	n)
	    # Kind of useless at the moment because this doesn't affect anything
	    # echo "Option 'd' was triggered with argument: $OPTARG"
	    list_len=$OPTARG;
	    ;;
	# t)
	    # Kind of useless at the moment because this doesn't affect anything
	    # echo "Option 'd' was triggered with argument: $OPTARG"
	    # thresh=$OPTARG
	    # ;;
	\?)
	    # Invalid option
	    echo "Invalid option: -$OPTARG"
	    exit 1
	    ;;
    esac
done

# After processing options, you can access non-option arguments (e.g., filenames) like this:
# shift $((OPTIND - 1))
# echo "Non-option arguments: $@"

pmeth=$(echo "$pmeth" | to_lower | beautify_pmeth);
eflav=$(echo "$eflav" | to_upper | beautify_eflav);
htype=$(to_upper "$htype");

logdir="logs/vary-cardinality"

if ! [ -d "$logdir" ];
then
    mkdir "$logdir"
fi
logfile="$logdir/$pmeth-$eflav-$htype-$secpar.csv"
echo "Logging Output to be stored in $logfile"

make --quiet clean;
make --quiet;

echo "START AVERAGE RUNTIME/BANDWIDTH TEST";
echo "sec par, # entries, threshold, expected matches, total bytes, total_time" > "$logfile";
for (( i=$min_percent; $i<=$max_percent; i+=10 ))
do
    for ((j=0; j<10; j++))
    do
	# setup_input_files -n "50" -s "$secpar" -f $(echo "scale=2; $i / 100" | bc)
	setup_input_files -n "50" -s "32" -f $(echo "scale=2; $i / 100" | bc)
	matches=$?
	printf "%s%d\n" "Begin: $pmeth $eflav $htype Protocol #" "$j"
	# exit
	./bin/main/client-and-server -p "$pmeth" -y "$secpar" -e "$eflav" -m "$htype" -t "$((50 / 3))" -x $matches -l "$logfile"
	#	$pids=$(ps aux | grep "elgamal" | grep -v "grep" | awk '{print $2}')
	wait
	printf "%s%d\n\n" "Finish:  $pmeth $eflav $htype Protocol #" "$j"
    done
    echo "-------------------------------------------" >> "$logfile";
done
echo "END AVERAGE RUNTIME/BANDWIDTH TEST";
