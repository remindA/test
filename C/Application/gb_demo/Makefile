#
# gb28181-log
#
include ../../Rule.mk
CFLAGS += -Os -Wall -s
BIN = gb28181-log

CFLAGS += -Wall -Os 

CFLAGS += -DIMP=\"$(IMP)\" -DPNUM=$(PNUM) -DWAN_INTERFACE=\"$(WAN_INTERFACE)\" -DLAN_INTERFACE=\"$(LAN_INTERFACE)\"

CFLAGS += -I. -I../../build/target/usr/include -I../iptables-1.4.4/include
LIBS= -L../bcmutils -lbcmutils -L../nvram -lnvram $(LIBNewPATH) -L../../build/target/usr/lib -lnetfilter_queue -lmnl -lnfnetlink -losipparser2 -losip2

CFLAGS += -DBUILDSTR=\"\"

#OBJS  =  main.o

OBJS  =  gb28181-log.o
OBJS += security.o
OBJS += log.o
OBJS += sip_utils.o
OBJS += sip_layer.o
OBJS += utils.o
OBJS += register.o
OBJS += auth.o
OBJS += sock.o

all: $(BIN)

$(BIN):  $(OBJS)
	$(CC)  $(CFLAGS) $(OBJS) $(LIBS) -o  $@ 
	@echo "make $@ finished on `date`"

%.o:	%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  $(LIBS) 

install:
	cp -a $(BIN) ../../target/usr/sbin

clean:
	rm -f $(BIN) $(OBJS) 
