BIN = connection_flood
OBJS = main.o utils_net.o
INCLUDES = -I. -I./include
CFLAGS = -Os -Wall
LIBS = 

.PHONY: all

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(OBJS) -o $(BIN) $(CFLAGS) $(LIBS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(INCLUDES)

clean:
	rm -rf $(BIN) $(OBJS)
