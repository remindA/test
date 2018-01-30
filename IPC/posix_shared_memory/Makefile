CFLAGS  = -Wall -Os -g
LIBS = -lrt -lpthread
INCLUDES = 
BIN = demo
OBJS = posix_shared_memory.o

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) -o $(BIN) $(OBJS) $(CFLAGS) $(INCLUDES) $(LIBS)
%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(INCLUDES) $(LIBS)

clean:
	rm -rf $(BIN) $(OBJS)
