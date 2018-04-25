CFLAGS = -Wall -g
INCLUDES = -I./ -I./include
LIBS = -luci

OBJS_UCI_EXPORT = uci_export.o
BIN_UCI_EXPORT  = uci_export
OBJS_UCI_SET = uci_set.o
BIN_UCI_SET  = uci_set
BIN_UCI_SET_OPT = uci_set_opt
BIN_UCI_SET_SEC = uci_set_sec

OBJS = $(OBJS_UCI_EXPORT)
OBJS+= $(OBJS_UCI_SET)

BINS = $(BIN_UCI_EXPORT)
BINS+= $(BIN_UCI_SET)
BINS+= $(BIN_UCI_SET_OPT)
BINS+= $(BIN_UCI_SET_SEC)

all: $(BINS)

%.o: %.c
	$(CC) -c $< $(CFLAGS) $(INCLUDES) $(LIBS) -o $@

clean:
	rm -rf $(BINS) $(OBJS)

###################################################################################

$(BIN_UCI_EXPORT): $(OBJS_UCI_EXPORT)
	$(CC) $(OBJS_UCI_EXPORT) $(CFLAGS) $(INCLUDES) $(LIBS) -o $(BIN_UCI_EXPORT)

clean_$(BIN_UCI_EXPORT):
	rm -rf $(OBJS_UCI_EXPORT) $(BIN_UCI_EXPORT)

###################################################################################

$(BIN_UCI_SET): $(OBJS_UCI_SET)
	$(CC) $(OBJS_UCI_SET) $(CFLAGS) $(INCLUDES) $(LIBS) -o $(BIN_UCI_SET)
	ln -s $(BIN_UCI_SET) uci_set_opt
	ln -s $(BIN_UCI_SET) uci_set_sec

clean_$(BIN_UCI_SET):
	rm -rf $(OBJS_UCI_SET) $(BIN_UCI_SET) $(BIN_UCI_SET_SEC) $(BIN_UCI_SET_OPT)
