CFLAGS  = -Wall -Os -g
LIBS = -lpthread
INCLUDES = 
BIN = shm_sysv
OBJS = shm_sysv.o

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) -o $(BIN) $(OBJS) $(CFLAGS) $(INCLUDES) $(LIBS)
%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(INCLUDES) $(LIBS)

clean:
	rm -rf $(BIN) $(OBJS)
