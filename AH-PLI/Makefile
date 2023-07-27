CC=gcc
LINK=-lcrypto
FLAGS=-g -Wall -Werror -Wpedantic -fsanitize=address
SRC=src
OBJ=obj
HDR=hdr
BIN=bin
SRCS=$(wildcard $(SRC)/*.c)
HDRS=$(wildcard $(HDR)/*.h)
OBJS=$(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SRCS))

EG_UTIL_OBJS=$(filter-out $(OBJ)/%client.o $(OBJ)/%server.o $(OBJ)/ec%, $(OBJS))
ECEG_UTIL_OBJS=$(filter-out $(OBJ)/%client.o $(OBJ)/%server.o $(OBJ)/elgamal%, $(OBJS))
CLSR_OBJS=$(filter $(OBJ)/%client.o $(OBJ)/%server.o, $(OBJS))

all: EG ECEG EG_BOTH ECEG_BOTH
# debugging commands
# $(info SRCS: $(SRCS))
# $(info HDRS: $(HDRS))
# $(info EG_UTIL_OBJS: $(EG_UTIL_OBJS))
# $(info ECEG_UTIL_OBJS: $(ECEG_UTIL_OBJS))
# $(info CLSR_OBJS: $(CLSR_OBJS))
# $(info OBJS: $(OBJS))

EG_BOTH: $(BIN)/elgamal-client-and-server
ECEG_BOTH: $(BIN)/ec-elgamal-client-and-server
EG: $(BIN)/elgamal-client $(BIN)/elgamal-server
ECEG: $(BIN)/ec-elgamal-client $(BIN)/ec-elgamal-server

$(BIN)/elgamal-%: $(OBJ)/elgamal-%.o $(EG_UTIL_OBJS)
	mkdir -p $(BIN)
	$(CC) $(FLAGS) $< $(EG_UTIL_OBJS) -o $@ $(LINK)

$(BIN)/ec-elgamal-%: $(OBJ)/ec-elgamal-%.o $(ECEG_UTIL_OBJS)
	$(CC) $(FLAGS) $< $(ECEG_UTIL_OBJS) -o $@ $(LINK)

$(BIN): $(OBJS)
	$(CC) $(FLAGS) $(OBJS) -o $@

$(OBJ)/%.o: $(SRC)/%.c
	mkdir -p $(OBJ)
	$(CC) $(FLAGS) -c $< -o $@

dry-run-clean:
	echo $(RM) -ri $(OBJ)/* $(BIN)/* $(SRC)/*~ $(HDR)/*~ | tr -s ' ' | cut -d ' ' -f 1-100 | fmt -w 1

clean:
	$(RM) -r $(OBJ)/* $(BIN)/* $(SRC)/*~ $(HDR)/*~
