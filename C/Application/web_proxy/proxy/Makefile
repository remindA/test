CFLAGS = -Wall -Os -s
CFLAGS += -D VERSION=\"1.0\"
CFLAGS += -D _GNU_SOURCE
INCLUDES = -I. -I./include
LIBS = -lpthread -lm 
OBJS =  server_epoll.o http.o socket_tools.o
BIN = server_epoll

##########################调试宏#############################
#CFLAGS += -D DEBUG
#CFLAGS += -D FUNC
#CFLAGS += -D DEBUG_HTTP
#CFLAGS += -D DEBUG_SSL
#CFLAGS += -D TIME_COST
##########################调试宏#############################



all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LIBS)
	@echo "make $@ finished on `date`"

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@


install:
	cp -rf $(BIN) /usr/sbin

clean:
	rm -rf $(BIN) $(OBJS)

uninstall:
	rm /usr/sbin/$(BIN)

