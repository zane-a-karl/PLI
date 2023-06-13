CC=gcc
LINK=-lcrypto
FLAGS=-g -Wall -fsanitize=address
SRC=src
OBJ=obj
HDR=hdr
CLIENT=$(SRC)/client-ah.c
SERVER=$(SRC)/server-ah.c
SRCS=$(filter-out $(CLIENT) $(SERVER),$(wildcard $(SRC)/*.c))
OBJS=$(filter-out $(CLIENT) $(SERVER),$(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SRCS)))
HDRS=$(filter-out $(CLIENT) $(SERVER),$(wildcard $(HDR)/*.h))
BIN=bin

all: $(BIN)/client $(BIN)/server

$(BIN)/client: $(OBJ)/client-ah.o

$(BIN)/server: $(OBJ)/server-ah.o

$(OBJ)/client-ah.o: $(CLIENT) $(OBJS)
	$(CC) $< $(FLAGS) $(OBJS) -o $@ $(LINK)

$(OBJ)/server-ah.o: $(SERVER) $(OBJS)
	$(CC) $< $(FLAGS) $(OBJS) -o $@ $(LINK)

$(BIN): $(OBJS)
	$(CC) $(FLAGS) $(OBJS) -o $@

$(OBJ)/%.o: $(SRC)/%.c
#	debugging commands
#	$(info SRCS: $(SRCS))
#	$(info HDRS: $(HDRS))
	$(CC) $(FLAGS) -c $< -o $@

dry-run-clean:
	echo $(RM) -ri $(OBJ)/* $(BIN)/* $(SRC)/*~ $(HDR)/*~ | tr -s ' ' | cut -d ' ' -f 1-100 | fmt -w 1

clean:
	$(RM) -r $(OBJ)/* $(BIN)/* $(SRC)/*~ $(HDR)/*~
