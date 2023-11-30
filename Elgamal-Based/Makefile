CC=gcc
LINK=-lcrypto
FLAGS := -g -Wall -Werror -Wpedantic
SRC=src
OBJ=obj
HDR=hdr
BIN=bin
MAIN=main
CRYPTO=crypto
ECEG=ecelgamal
EG=elgamal
ERROR=error
INPUT_ARGS="input-args"
LOGGING=logging
NETWORK=network
PROTOCOLS=protocols
SRCS=$(wildcard $(SRC)/*.c) $(wildcard $(SRC)/**/*.c)
HDRS=$(wildcard $(HDR)/*.h) $(wildcard $(HDR)/**/*.h)
OBJS=$(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SRCS))

NOT_MAIN_OBJS=$(filter-out $(OBJ)/$(MAIN)%.o, $(OBJS))
MAIN_OBJS=$(filter $(OBJ)/$(MAIN)%.o, $(OBJS))

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
        # Linux-specific flags
	LINK += -lbsd
else ifeq ($(UNAME_S),Darwin)
        # macOS-specific flags
	FLAGS := -fsanitize=address $(FLAGS)
else
	$(error Unsupported operating system: $(UNAME_S))
endif

all: DIR_SETUP CLIENT SERVER CLIENT_AND_SERVER

DEBUG:
	$(info SRCS: $(SRCS))
	$(info HDRS: $(HDRS))
	$(info OBJS: $(OBJS))
	$(info NOT_MAIN_OBJS: $(NOT_MAIN_OBJS))
	$(info MAIN_OBJS:  $(MAIN_OBJS))

DIR_SETUP:
	if ! [ -d $(BIN) ]; then mkdir $(BIN); fi
	if ! [ -d $(BIN)/$(MAIN) ]; then mkdir $(BIN)/$(MAIN); fi
	if ! [ -d $(OBJ) ]; then mkdir $(OBJ); fi
	if ! [ -d $(OBJ)/$(MAIN) ]; then mkdir $(OBJ)/$(MAIN); fi
	if ! [ -d $(OBJ)/$(CRYPTO) ]; then mkdir $(OBJ)/$(CRYPTO); fi
	if ! [ -d $(OBJ)/$(ECEG) ]; then mkdir $(OBJ)/$(ECEG); fi
	if ! [ -d $(OBJ)/$(EG) ]; then mkdir $(OBJ)/$(EG); fi
	if ! [ -d $(OBJ)/$(ERROR) ]; then mkdir $(OBJ)/$(ERROR); fi
	if ! [ -d $(OBJ)/$(INPUT_ARGS) ]; then mkdir $(OBJ)/$(INPUT_ARGS); fi
	if ! [ -d $(OBJ)/$(LOGGING) ]; then mkdir $(OBJ)/$(LOGGING); fi
	if ! [ -d $(OBJ)/$(NETWORK) ]; then mkdir $(OBJ)/$(NETWORK); fi
	if ! [ -d $(OBJ)/$(PROTOCOLS) ]; then mkdir $(OBJ)/$(PROTOCOLS); fi

CLIENT: $(BIN)/$(MAIN)/client
SERVER: $(BIN)/$(MAIN)/server
CLIENT_AND_SERVER: $(BIN)/$(MAIN)/client-and-server

$(BIN)/$(MAIN)/%: $(OBJ)/$(MAIN)/%.o $(NOT_MAIN_OBJS)
	$(CC) $(FLAGS) $< $(NOT_MAIN_OBJS) -o $@ $(LINK)

$(BIN): $(OBJS)
	$(CC) $(FLAGS) $(OBJS) -o $@

$(OBJ)/%.o: $(SRC)/%.c
	$(CC) $(FLAGS) -c $< -o $@

dry-run-clean:
	echo $(RM) -ri $(OBJ)/* $(BIN)/* $(SRC)/*~ $(HDR)/*~ | \
tr -s ' ' | cut -d ' ' -f 1-100 | fmt -w 1

clean:
	$(RM) -r $(OBJ)/* $(BIN)/* $(SRC)/*~ $(HDR)/*~
