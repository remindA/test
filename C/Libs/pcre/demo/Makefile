BIN=demo
OBJS=demo_find_all_substring.o 
CFLAGS= -Os -Wall -g
CFLAGS+= -D NAMED_GROUP
LIBS=-lpcre2-8 -lm
INCLUDES = -I. -I./include

##### 调试宏 #####
CFLAGS += -D DEBUG
CFLAGS += -D NAMED_GROUP
##### 调试宏 #####


$(BIN):$(OBJS)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJS) $(LIBS)

$(OBJS):%.o:%.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c $<  

clean:
	rm -rf $(BIN) $(OBJS)
