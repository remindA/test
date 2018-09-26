BIN = simulate
OBJS = main.o utils_net.o
CFLAGS = -Os -Wall
LIBS =
INCLUDES = -I. -I./include

$(BIN): $(OBJS)
	$(CC) $(OBJS) -o $(BIN) $(LIBS)
	
%.o: %.c
	$(CC) -c $< -o $@ $(INCLUDES) $(CFLAGS)

clean:
	rm -rf $(BIN) $(OBJS)
