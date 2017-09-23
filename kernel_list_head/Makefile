CC=gcc
LD=ld
LIBS=
CFLAGS= -Os -Wall
BIN=node_str
OBJS=node_substr_test.o

all:$(BIN)

$(BIN):$(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(BIN) $(LIBS)

$(OBJS): %.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LIBS)

clean:
	rm -rf $(BIN) $(OBJS)
