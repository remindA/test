BIN = queue_udp
OBJS  =  main.o
CFLAGS += -Os -Wall -s
CFLAGS += -D GB_DEBUG
CFLAGS += -D DEBUG_FUNC
CFLAGS += -D DEBUG_PRINT
INCLUDES = -I. -I./include

LIBS = -lnetfilter_queue -lmnl -lnfnetlink


all: $(BIN)

.PHONY: all

$(BIN): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LIBS)
	@echo "make $@ finished on `date`"

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(INCLUDES)


clean:
	rm -f $(BIN) $(OBJS)
