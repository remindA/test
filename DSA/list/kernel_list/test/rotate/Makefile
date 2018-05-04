BIN = main
OBJS = main.o john_ring.o


LIBS = 
FLAGS = 
INCLUDES = -I. -I./include

CC = gcc



$(BIN):$(OBJS)
	$(CC) $(FLAGS) $(OBJS) -o $@ $(INCLUDES) $(LIBS)

%.o:%.c
	$(CC) $(FLAGS) -c $< -o $@ $(INCLUDES)

clean:
	rm -rf $(BIN) $(OBJS)
