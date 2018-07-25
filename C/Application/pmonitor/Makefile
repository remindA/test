BIN = pmonitor
OBJS = pmonitor.o utils_net.o

CFLAGS = -Wall -Os
INC = -I. -I./include
LIBS = 

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(OBJS) -o $(BIN) $(LIBS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(INC)

clean:
	rm -rf $(BIN) $(OBJS)
