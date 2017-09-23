CC 	= gcc
BIN 	= client
OBJS 	= openssl_client.o  if_info.o
CFLAGS 	= -Wall -Os -I./include
LIBS 	= -lssl -lcrypto -lpthread
$(BIN):$(OBJS)
	$(CC) $(OBJS) $(LIBS) -o $(BIN) 

clean:
	rm -rf $(BIN) $(OBJS) *~

