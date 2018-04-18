BIN = main
OBJS = main.o john_ring.o

BIN2 = main2
OBJS2 = main2.o john_ring.o

LIBS = 
FLAGS = 
INCLUDES = -I. -I./include

CC = gcc

clean:
	rm -rf $(BIN) $(OBJS)

clean2:
	rm -rf $(BIN2) $(OBJS2)

$(BIN):$(OBJS)
	$(CC) $(FLAGS) $(OBJS) -o $@ $(INCLUDES) $(LIBS)

$(BIN2):$(OBJS2)
	$(CC) $(FLAGS) $(OBJS2) -o $@ $(INCLUDES) $(LIBS)

%.o:%.c
	$(CC) $(FLAGS) -c $< -o $@ $(INCLUDES)
