#the value of PLATFORM is either SR04I or OpenWRT
SERVER_KEY = server.key
SERVER_CRT = server.crt
CFLAGS = -Wall -Os -s
CFLAGS += -D VERSION=\"1.0_20180515\"
INCLUDES = -I. -I./include
OBJS =  http_proxy.o http.o
BIN = http_proxy

##########################调试宏#############################
CFLAGS += -D DEBUG
CFLAGS += -D FUNC
CFLAGS += -D DEBUG_HTTP
CFLAGS += -D DEBUG_SSL
CFLAGS += -D PADDEBUG
CFLAGS += -D NAMED_GROUP
CFLAGS += -D PRINTMATCH
CFLAGS += -D STRDEBUG
CFLAGS += -D RPS
CFLAGS += -D HANDLE_CLIENT
CFLAGS += -D HANDLE_SERVER
CFLAGS += -D NO_REPLACE
CFLAGS += -D TIME_COST
##########################调试宏#############################




LIBS = -lssl -lcrypto -lm -lz -lpthread




all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LIBS)
	@echo "make $@ finished on `date`"

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@ $(LIBS)


install:
	cp -a $(BIN) ../../target/usr/sbin

clean:
	rm -rf $(BIN) $(OBJS)
