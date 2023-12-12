# Elgamal-based Private List Intersection (PLI)

## Purpose

The purpose of this project subdirectory is to provide the necessary functions for a programmer
to test additively and multiplicatively homomorphic versions of the Elgamal encryption system
applied to the problem of private list intersection.

## Organization

The subdirectory is organized as follows:

	- C source files are located in the `src/` trunk
	- C header files are located in the `hdr/` trunk
	- Linkable object files are located in the `obj/` trunk
	- Executable binary files are located in the `bin/` trunk
	- Program input files are located in the `input/` trunk
	- Automatic compilation and testing scripts are located in the `scripts/` trunk
	- Output logs from the scripts are located in the `logs/` trunk

## Dependencies

	- C compiler (e.g. gcc)
	- libssl-dev
		- brew install openssl@3
		- apt-get install libssl-dev
	- libbsd-dev (Linux only)
		- apt-get install libbsd-dev
	- make
	- bc

## Compilation and Execution Instructions

On macOS:

	1. `cd Elgamal-Based/`
	2. `make`
	3. Now you have some options:
	    - Running a client and server in two separate terminals:
		    - `source ./scripts/helpers.sh`
			- `setup_input_files -n <# of list entries> -s <security parameter in # bits> -f <fraction of matches>`
		    - Open two terminals
			- In the one terminal run:
				- `./bin/main/server =p <pli method> -e <EG or ECEG> -h <AH or MH> -y <security param> -t <threshold> -s input/server.txt`
		    - In the other run:
				- `./bin/main/client -h <hostname> -p <pli method> -e <EG or ECEG> -m <AH or MH> -y <security param> -c input/client.txt`
		- Running a client and server from the same terminal:
			- `./bin/main/client-and-server -h <hostname> -p <pli method> -e <EG or ECEG> -m <AH or MH> -y <security param> -s input/server.txt -c input/client.txt`

	4. To run the benchamrking script:
		- Run `chmod +x scripts/<name of Elgamal script you'd like to run>`
		- `./scripts/benchmark-single-protocol -p <pli method> -e <EG or ECEG> -m <AH or MH> -y <security param> -n <# entries>`
