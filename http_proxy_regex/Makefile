CFLAGS += -Os -Wall -s -g
#CFLAGS += -g
CFLAGS += -I. -I./include 
#DEBUG,NAMED_GROUP等宏用于调试
CFLAGS+= -D DEBUG
#CFLAGS+= -D STRDEBUG
#CFLAGS+= -D HTTPDEBUG
#CFLAGS+= -D PADDEBUG
#CFLAGS+= -D NAMED_GROUP
LIBS= -lpcre2-8 -lm
BIN = http_proxy_regex
OBJS = demo.o str_replace.o pad_rplstr.o http_rpl.o

all: $(BIN)

http_proxy_regex:  $(OBJS)
	$(CC)  $(CFLAGS) $(OBJS) -o $@ $(LIBS)
	@echo "make $@ finished on `date`"

%.o:	%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@ $(LIBS) 

clean:
	rm -f $(BIN) $(OBJS) 
