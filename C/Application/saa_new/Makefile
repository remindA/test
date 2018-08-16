include ../../Rule.mk
BIN = saa
OBJS = saa.o utils_net.o ipset.o
OBJS += config_sr04i.o

CFLAGS = -Wall -Os $(LIBNewPATH)
INC = -I. -I./include -I../openssl-1.0.2k/include
LIBS = -L../openssl-1.0.2k -lssl -lcrypto
all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(OBJS) -o $(BIN) $(LIBS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(INC)

clean:
	rm -rf $(BIN) $(OBJS)
