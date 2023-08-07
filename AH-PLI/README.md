# Elgamal-based Private List Intersection(PLI)

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

## Compilation and Execution Instructions

To compile and execute on a Mac or other Unix-based system you must follow the following steps:

	- If you are not already in the `AH-PLI/` trunk `cd` into it.
	- Run `make`
	- Now you have some options:

	    - Running a client and server in two separate terminals:

		    - Optionally run `source ./scripts/helpers.sh` followed by `setup_input_files <# entries>`
		    - In one terminal run `./bin/server <pli method> <security param> input/server.txt <EG or ECEG> <AH or MH>`
		    - In another terminal run `./bin/client <hostname> <pli method> <security param> input/client.txt <EG or ECEG> <AH or MH>`
		- Running a client and server from the same terminal run `./bin/client-and-server <hostname> <pli method> <security param> input/server.txt input/client.txt <EG or ECEG> <AH or MH>`

To run the benchamrking script:
    - Run `chmod +x <name of Elgamal script you'd like to run>`
    - Note you do not need to run `make` as the automatic script will do so itself
    - Run `./scripts/benchmark-single-protocol <pli method> <EG or ECEG> <AH or MH> <security param>`
