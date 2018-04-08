#the value of PLATFORM is either SR04I or OpenWRT
PLATFORM = OpenWRT

CFLAGS = -Wall -Os -s
CFLAGS += -D $(PLATFORM)
CFLAGS += -D VERSION=\"0.1-only_packet_filter\"
INCLUDES = -I. -I./include
OBJS =  main.o zone.o pool.o policy.o iptables.o
BIN = hxha_firewall

##########################调试宏#############################
#CFLAGS += -D DEBUG
#CFLAGS += -D FUNC
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
LIBS += -luci 


else ifeq ($(PLATFORM), x86)
LIBS = -luci
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
