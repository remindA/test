BIN = main
OBJS = main.o polynomial.o
LIBS = 
FLAGS = 
INCLUDES = -I. -I./include

CC = gcc

all:$(BIN)

clean:
	rm -rf $(BIN) $(OBJS)

$(BIN):$(OBJS)
	$(CC) $(FLAGS) $(OBJS) -o $@ $(INCLUDES) $(LIBS)

%.o:%.c
	$(CC) $(FLAGS) -c $< -o $@ $(INCLUDES)
