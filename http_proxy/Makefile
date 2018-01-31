#the value of PLATFORM is either SR04I or OpenWRT
PLATFORM = SR04I

CA_CRT = ca.crt
SERVER_KEY = server.key
SERVER_CRT = server.crt
CFLAGS = -Wall -Os -s
CFLAGS += -D $(PLATFORM)
CFLAGS += -D VERSION=\"1.3-多线程\"
OBJS =  http_proxy.o config.o http.o pad_rplstr.o str_replace.o
BIN = http_proxy

##########################调试宏#############################
#CFLAGS += -D DEBUG
#CFLAGS += -D FUNC
#CFLAGS += -D DEBUG_HTTP
#CFLAGS += -D PADDEBUG
#CFLAGS += -D NAMED_GROUP
#CFLAGS += -D PRINTMATCH
#CFLAGS += -D STRDEBUG
#CFLAGS += -D RPS
#CFLAGS += -D HANDLE_CLIENT
#CFLAGS += -D HANDLE_SERVER
#CFLAGS += -D NO_REPLACE
#CFLAGS += -D TIME_COST
##########################调试宏#############################


ifeq ($(PLATFORM), SR04I)
include ../../Rule.mk
INC_KERNEL_PATH = ../../kernel/linux/include
OBJS += socket_tools.o
CFLAGS += -DIMP=\"$(IMP)\" -DPNUM=$(PNUM) -DWAN_INTERFACE=\"$(WAN_INTERFACE)\" -DLAN_INTERFACE=\"$(LAN_INTERFACE)\"
INCLUDES = -I. -I./include -I$(INC_KERNEL_PATH)
INCLUDES += -I../bcmutils  -I../nvram  -I../../build/target/usr/include
LIBS =  -L../bcmutils -lbcmutils -L../nvram -lnvram 
LIBS += -L../../build/target/usr/lib -lpcre2-8
LIBS += -L../openssl-1.0.2k -lssl -lcrypto
LIBS += -Wl,-rpath,/lib/
LIBS += $(LIBNewPATH) -lz -lm -lpthread
#openssl库, ELDK自带openssl库,但是版本太老,还不支持TLSv1.2


else ifeq ($(PLATFORM), OpenWRT)
INCLUDES = -I. -I./include
LIBS += -lssl -lcrypto -lpcre2-8 -lz -lm -lrt -lpthread -luci


else ifeq ($(PLATFORM), x86)
INCLUDES = -I. -I./include
LIBS = -lssl -lcrypto -lpcre2-8 -lz -lm -lrt -lpthread
endif




all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LIBS)
	@echo "make $@ finished on `date`"

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@ $(LIBS)

install:
	cp -a $(BIN) ../../target/usr/sbin
	cp $(CA_CRT) ../../target/usr/ 

clean:
	rm -rf $(BIN) $(OBJS)
