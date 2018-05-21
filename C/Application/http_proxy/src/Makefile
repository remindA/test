#the value of PLATFORM is either SR04I or OpenWRT
PLATFORM = OpenWRT
GDB = YES

SERVER_KEY = server.key
SERVER_CRT = server.crt
CFLAGS = -Wall -Os -s
CFLAGS += -D $(PLATFORM)
CFLAGS += -D VERSION=\"1.3_180202多线程\"
INCLUDES = -I. -I./include
OBJS =  http_proxy.o config.o http.o pad_rplstr.o str_replace.o
BIN = http_proxy

ifeq ($(GDB), YES)
CFLAGS += -g
endif

##########################调试宏#############################
#CFLAGS += -D DEBUG
#CFLAGS += -D FUNC
#CFLAGS += -D DEBUG_HTTP
#CFLAGS += -D DEBUG_SSL
#CFLAGS += -D PADDEBUG
#CFLAGS += -D NAMED_GROUP
#CFLAGS += -D PRINTMATCH
#CFLAGS += -D STRDEBUG
#:wCFLAGS += -D RPS
#CFLAGS += -D HANDLE_CLIENT
#CFLAGS += -D HANDLE_SERVER
#CFLAGS += -D NO_REPLACE
#CFLAGS += -D TIME_COST
#CFLAGS += -D DEBUG_SIGNAL
##########################调试宏#############################


ifeq ($(PLATFORM), SR04I)
include ../../Rule.mk
INC_KERNEL_PATH = ../../kernel/linux/include
OBJS += socket_tools.o
CFLAGS += -DIMP=\"$(IMP)\" -DPNUM=$(PNUM) -DWAN_INTERFACE=\"$(WAN_INTERFACE)\" -DLAN_INTERFACE=\"$(LAN_INTERFACE)\"
INCLUDES += -I$(INC_KERNEL_PATH)
INCLUDES += -I../bcmutils  -I../nvram  -I../../build/target/usr/include
INCLUDES += -I../openssl-1.0.2k/include
LIBS =  -L../bcmutils -lbcmutils -L../nvram -lnvram 
LIBS += -L../openssl-1.0.2k -lssl -lcrypto
LIBS += -L../../build/target/usr/lib -lpcre2-8
LIBS += $(LIBNewPATH) -lm -lz -lpthread

else ifeq ($(PLATFORM), OpenWRT)
LIBS += -lssl -lcrypto -lpcre2-8 -luci -lm -lz -lpthread -lhregister


else ifeq ($(PLATFORM), x86)
LIBS = -lssl -lcrypto -lpcre2-8 -lm -lz -lpthread
endif




all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LIBS)
	@echo "make $@ finished on `date`"

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@ $(LIBS)


install:
	cp -a $(BIN) ../../target/usr/sbin

clean:
	rm -rf $(BIN) $(OBJS)
