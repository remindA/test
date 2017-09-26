CROSS_COMPILE=
CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld
AS=$(CROSS_COMPILE)as
AR=$(CROSS_COMPILE)ar
NM=$(CROSS_COMPILE)nm
STRIP=$(CROSS_COMPILE)strip
OBJCOPY=$(CROSS_COMPILE)objcopy
OBJDUMP=$(CROSS_COMPILE)objdump
TARGET_PREFIX=mips_4KCle-
#LIBS = -Wl,--rpath-link,/opt/ELDK/mips_4KCle/lib,/opt/ELDK/mips_4KCle/usr/lib
LIBS=-lpcre2-8 -lm
CFLAGS= -Os -Wall -g
#DEBUG和NAMED_GROUP宏用于调试
CFLAGS+= -D DEBUG
CFLAGS+= -D NAMED_GROUP
BIN=demo
OBJS=demo.o str_replace.o pad_rplstr.o http_rpl.o socket_tools.o


all: echo $(BIN) $(OBJS)

echo:
	@echo $(CC)
	@echo $(LIBS)
$(BIN):$(OBJS)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJS) $(LIBS)

$(OBJS):%.o:%.c
	$(CC) $(CFLAGS) -o $@ -c $<  

clean:
	rm -rf $(BIN) $(OBJS)
