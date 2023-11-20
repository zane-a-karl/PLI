CC=gcc
LINK=-lpaillier -lgmp -lbloom
FLAGS=-g -Wall -Werror -Wpedantic -fsanitize=address
#FLAGS=-g -Wall -Wpedantic -fsanitize=address
SRC=src
OBJ=obj
HDR=hdr
BIN=bin
SRCS=$(wildcard $(SRC)/*.c)
HDRS=$(wildcard $(HDR)/*.h)
OBJS=$(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SRCS))

UTIL_OBJS=$(filter-out $(OBJ)/%client.o $(OBJ)/%server.o, $(OBJS))
CLSR_OBJS=$(filter $(OBJ)/%client.o $(OBJ)/%server.o, $(OBJS))

all: BF_PAILLIER BOTH
# debugging commands
# $(info SRCS: $(SRCS))
# $(info HDRS: $(HDRS))
# $(info UTIL_OBJS: $(UTIL_OBJS))
# $(info CLSR_OBJS: $(CLSR_OBJS))
# $(info OBJS: $(OBJS))

BOTH: $(BIN)/bfp-client-and-server
BF_PAILLIER: $(BIN)/bfp-client $(BIN)/bfp-server

$(BIN)/bfp-%: $(OBJ)/bfp-%.o $(UTIL_OBJS)
	$(CC) $(FLAGS) $< $(UTIL_OBJS) -o $@ $(LINK)

$(BIN): $(OBJS)
	$(CC) $(FLAGS) $(OBJS) -o $@

$(OBJ)/%.o: $(SRC)/%.c
	$(CC) $(FLAGS) -c $< -o $@

dry-run-clean:
	echo $(RM) -ri $(OBJ)/* $(BIN)/* $(SRC)/*~ $(HDR)/*~ | tr -s ' ' | cut -d ' ' -f 1-100 | fmt -w 1

clean:
	$(RM) -r $(OBJ)/* $(BIN)/* $(SRC)/*~ $(HDR)/*~
