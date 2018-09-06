UDP_ECHO = udp_echo
OBJS_UDP_ECHO = udp_echo.o utils_net.o
UDP_TEST = udp_test
OBJS_UDP_TEST = udp_test.o utils_net.o
CFLAGS = -Os -Wall -s
INCLUDES = -I. -I./include
LIBS = 


all: $(UDP_ECHO) $(UDP_TEST)
.PHONY: all

$(UDP_ECHO): $(OBJS_UDP_ECHO)
	$(CC) $(OBJS_UDP_ECHO) -o $@

$(UDP_TEST): $(OBJS_UDP_TEST)
	$(CC) $(OBJS_UDP_TEST) -o $@

%.o: %.c
	$(CC) -c $< -o $@ $(INCLUDES) $(CFLAGS)

clean:
	rm -rf $(UDP_ECHO) $(UDP_TEST) *.o

