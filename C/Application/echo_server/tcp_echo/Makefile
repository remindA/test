TCP_ECHO = tcp_echo
OBJS_TCP_ECHO = tcp_echo.o utils_net.o
CFLAGS = -Os -Wall -s
INCLUDES = -I. -I./include
LIBS = 


all: $(TCP_ECHO)
.PHONY: all

$(TCP_ECHO): $(OBJS_TCP_ECHO)
	$(CC) $(OBJS_TCP_ECHO) -o $@

%.o: %.c
	$(CC) -c $< -o $@ $(INCLUDES) $(CFLAGS)

clean:
	rm -rf $(TCP_ECHO) *.o

