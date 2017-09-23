CC 	= gcc
BIN 	= server
OBJS 	= openssl_server.o
CFLAGS 	= -Wall -Os -I.
LIBS 	= -lssl -lcrypto
$(BIN):$(OBJS)
	$(CC) $(OBJS) $(LIBS) -o $(BIN) 

clean:
	rm -rf $(BIN) $(OBJS) *~

