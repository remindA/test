CFLAGS  = -Wall -Os
CFLAGS += -D DEBUG
INCLUDES = -I. -I./include

#openssl
LIBS = -lssl -lcrypto 
#pcre2
#LIBS += -lpcre2-8
#zlib
#LIBS += -lz
#math
#LIBS += -lm
#posix ipc library
#LIBS += lrt
#posix thread library
#LIBS += lpthread


OBJS = openssl_client.o

BIN = client

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) -o $(BIN) $(OBJS) $(CFLAGS) $(INCLUDES) $(LIBS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(INCLUDES) $(LIBS)

clean:
	rm -rf $(BIN) $(OBJS)
