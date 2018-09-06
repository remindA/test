BIN_EHOME = ehome
OBJS_EHOME = ehome.o

CFLAGS = -Os -Wall
INCLUDES = -I. -I./include
LIBS = libezxml.a

.PHONY: all

all: $(BIN_EHOME)

$(BIN_EHOME): $(OBJS_EHOME)
	$(CC) $(OBJS_EHOME) $(LIBS) -o $@

%.o: %.c
	$(CC) -c $< -o $@ $(INCLUDES) $(CFLAGS)

.PHONY: clean

clean_main = clean_main 
clean: $(clean_main)

$(clean_main):
	rm -rf $(BIN_EHOME) $(OBJS_EHOME)

